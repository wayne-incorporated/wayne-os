// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/partition_manager.h"

#include <utility>
#include <unistd.h>
#include <vector>

#include <linux/capability.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/containers/contains.h>
#include <base/strings/stringprintf.h>

#include "cros-disks/disk.h"
#include "cros-disks/disk_monitor.h"
#include "cros-disks/quote.h"

namespace cros_disks {

namespace {

const char kPartitionProgramPath[] = "/sbin/sfdisk";

// MBR 2TB limit: (2^32 -1) partition size in sectors * 512 bytes/sectors
const uint64_t kMBRMaxSize = 2199023255040ULL;

// Initialises the process for partitionting and starts it.
PartitionError StartPartitionProcess(const base::FilePath& device_file,
                                     const std::string& partition_program,
                                     const std::string& label_type,
                                     const std::string& partition_input,
                                     SandboxedProcess* process) {
  process->SetNoNewPrivileges();
  process->NewMountNamespace();
  process->NewIpcNamespace();
  process->NewNetworkNamespace();
  process->SetCapabilities(CAP_TO_MASK(CAP_SYS_ADMIN));

  if (!process->EnterPivotRoot()) {
    LOG(WARNING) << "Could not enter pivot root";
    return PartitionError::kProgramFailed;
  }
  if (!process->SetUpMinimalMounts()) {
    LOG(WARNING) << "Could not set up minimal mounts for jail";
    return PartitionError::kProgramFailed;
  }

  // Open device_file so we can pass only the fd path to the partition program.
  base::File dev_file(device_file, base::File::FLAG_OPEN |
                                       base::File::FLAG_READ |
                                       base::File::FLAG_WRITE);
  if (!dev_file.IsValid()) {
    PLOG(ERROR) << "Cannot open " << quote(device_file) << " for partitioning: "
                << base::File::ErrorToString(dev_file.error_details());
    return PartitionError::kProgramFailed;
  }

  process->AddArgument(partition_program);
  process->AddArgument("--no-reread");
  process->AddArgument("--label");
  process->AddArgument(label_type);

  process->AddArgument("--wipe");
  process->AddArgument("always");
  process->AddArgument("--wipe-partitions");
  process->AddArgument("always");

  process->AddArgument(
      base::StringPrintf("/dev/fd/%d", dev_file.GetPlatformFile()));
  process->PreserveFile(dev_file.GetPlatformFile());

  process->SetStdIn(partition_input);

  if (!process->Start()) {
    LOG(WARNING) << "Cannot start process " << quote(partition_program)
                 << " to partition " << quote(device_file);
    return PartitionError::kProgramFailed;
  }

  return PartitionError::kSuccess;
}

}  // namespace

void PartitionManager::StartSinglePartitionFormat(
    const base::FilePath& device_path,
    cros_disks::PartitionCompleteCallback callback) {
  if (!base::PathExists(base::FilePath(kPartitionProgramPath))) {
    LOG(WARNING) << "Could not find a partition program "
                 << quote(kPartitionProgramPath);
    std::move(callback).Run(device_path, PartitionError::kProgramNotFound);
    return;
  }

  if (device_path.empty()) {
    LOG(ERROR) << "Device path is empty";
    std::move(callback).Run(device_path, PartitionError::kInvalidDevicePath);
    return;
  }

  if (base::Contains(partition_process_, device_path)) {
    LOG(WARNING) << "Device " << quote(device_path)
                 << " is already being partitioned";
    std::move(callback).Run(device_path,
                            PartitionError::kDeviceBeingPartitioned);
    return;
  }

  Disk disk;
  if (!disk_monitor_->GetDiskByDevicePath(device_path, &disk)) {
    LOG(ERROR) << "Cannot get properties of " << quote(device_path);
    std::move(callback).Run(device_path, PartitionError::kUnknownError);
    return;
  }

  std::string label_type;
  std::string partition_type;
  // MBR only supports <2TB disks.
  if (disk.device_capacity < kMBRMaxSize) {
    label_type = "mbr";
    // Hex code for partition type of FAT32 with LBA
    partition_type = "id=c";
  } else {
    label_type = "gpt";
    // Basic data partition (BDP) GUID
    partition_type = "type=EBD0A0A2-B9E5-4433-87C0-68B6B72699C7";
  }

  std::unique_ptr<SandboxedProcess> process = CreateSandboxedProcess();
  partition_process_.insert(device_path);

  PartitionError error =
      StartPartitionProcess(device_path, kPartitionProgramPath, label_type,
                            partition_type, process.get());
  if (error != PartitionError::kSuccess) {
    partition_process_.erase(device_path);
    std::move(callback).Run(device_path, error);
    return;
  } else {
    process_reaper_->WatchForChild(
        FROM_HERE, process->pid(),
        base::BindOnce(&PartitionManager::OnPartitionProcessTerminated,
                       weak_ptr_factory_.GetWeakPtr(), device_path,
                       std::move(callback)));
  }
}

void PartitionManager::OnPartitionProcessTerminated(
    const base::FilePath& device_path,
    cros_disks::PartitionCompleteCallback callback,
    const siginfo_t& info) {
  partition_process_.erase(device_path);
  PartitionError error_type = PartitionError::kUnknownError;
  switch (info.si_code) {
    case CLD_EXITED:
      if (info.si_status == 0) {
        error_type = PartitionError::kSuccess;
        LOG(INFO) << "Process " << info.si_pid << " for partitionting "
                  << quote(device_path) << " completed successfully";
      } else {
        error_type = PartitionError::kProgramFailed;
        LOG(ERROR) << "Process " << info.si_pid << " for partitionting "
                   << quote(device_path) << " exited with a status "
                   << info.si_status;
      }
      break;

    case CLD_DUMPED:
    case CLD_KILLED:
      error_type = PartitionError::kProgramFailed;
      LOG(ERROR) << "Process " << info.si_pid << " for partitionting "
                 << quote(device_path) << " killed by a signal "
                 << info.si_status;
      break;

    default:
      break;
  }
  std::move(callback).Run(device_path, error_type);
}

std::unique_ptr<SandboxedProcess> PartitionManager::CreateSandboxedProcess()
    const {
  return std::make_unique<SandboxedProcess>();
}

}  // namespace cros_disks
