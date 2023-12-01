// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/rename_manager.h"

#include <linux/capability.h>

#include <string>

#include <base/containers/contains.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <brillo/process/process.h>

#include "cros-disks/filesystem_label.h"
#include "cros-disks/platform.h"
#include "cros-disks/quote.h"
#include "cros-disks/rename_manager_observer_interface.h"

namespace cros_disks {

namespace {

struct RenameParameters {
  const char* filesystem_type;
  const char* program_path;
  const char* rename_group;
};

const char kRenameUser[] = "cros-disks";

// Supported file systems and their parameters
const RenameParameters kSupportedRenameParameters[] = {
    {"vfat", "/usr/sbin/fatlabel", "disk"},
    {"exfat", "/usr/sbin/exfatlabel", "fuse-exfat"},
    {"ntfs", "/usr/sbin/ntfslabel", "ntfs-3g"}};

const RenameParameters* FindRenameParameters(
    const std::string& filesystem_type) {
  for (const auto& parameters : kSupportedRenameParameters) {
    if (filesystem_type == parameters.filesystem_type) {
      return &parameters;
    }
  }

  return nullptr;
}

RenameError LabelErrorToRenameError(LabelError error_code) {
  switch (error_code) {
    case LabelError::kSuccess:
      return RenameError::kSuccess;
    case LabelError::kUnsupportedFilesystem:
      return RenameError::kUnsupportedFilesystem;
    case LabelError::kLongName:
      return RenameError::kLongName;
    case LabelError::kInvalidCharacter:
      return RenameError::kInvalidCharacter;
  }
}

}  // namespace

RenameManager::RenameManager(Platform* platform,
                             brillo::ProcessReaper* process_reaper)
    : platform_(platform),
      process_reaper_(process_reaper),
      weak_ptr_factory_(this) {}

RenameManager::~RenameManager() = default;

RenameError RenameManager::StartRenaming(const std::string& device_path,
                                         const std::string& device_file,
                                         const std::string& volume_name,
                                         const std::string& filesystem_type) {
  std::string source_path;
  if (!platform_->GetRealPath(device_path, &source_path) ||
      !CanRename(source_path)) {
    LOG(WARNING) << "Device with path " << quote(device_path)
                 << " is not allowed for renaming";
    return RenameError::kDeviceNotAllowed;
  }

  LabelError label_error = ValidateVolumeLabel(volume_name, filesystem_type);
  if (label_error != LabelError::kSuccess) {
    return LabelErrorToRenameError(label_error);
  }

  const RenameParameters* parameters = FindRenameParameters(filesystem_type);
  // Check if tool for renaming exists
  if (!base::PathExists(base::FilePath(parameters->program_path))) {
    LOG(WARNING) << "Cannot find a rename program for filesystem "
                 << quote(filesystem_type);
    return RenameError::kRenameProgramNotFound;
  }

  if (base::Contains(rename_process_, device_path)) {
    LOG(WARNING) << "Device " << quote(device_path)
                 << " is already being renamed";
    return RenameError::kDeviceBeingRenamed;
  }

  uid_t rename_user_id;
  gid_t rename_group_id;
  if (!platform_->GetUserAndGroupId(kRenameUser, &rename_user_id, nullptr) ||
      !platform_->GetGroupId(parameters->rename_group, &rename_group_id)) {
    LOG(WARNING) << "Cannot find a user with name " << quote(kRenameUser)
                 << " or a group with name " << quote(parameters->rename_group);
    return RenameError::kInternalError;
  }

  // TODO(klemenko): Further restrict the capabilities
  SandboxedProcess* process = &rename_process_[device_path];
  process->SetUserId(rename_user_id);
  process->SetGroupId(rename_group_id);
  process->SetNoNewPrivileges();
  process->NewMountNamespace();
  process->NewIpcNamespace();
  process->NewNetworkNamespace();
  process->SetCapabilities(0);

  process->AddArgument(parameters->program_path);

  // TODO(klemenko): To improve and provide more general solution, the
  // per-filesystem argument setup should be parameterized with RenameParameter.
  // Construct program-name arguments
  // Example: dosfslabel /dev/sdb1 "NEWNAME"
  // Example: exfatlabel /dev/sdb1 "NEWNAME"
  if (filesystem_type == "vfat" || filesystem_type == "exfat" ||
      filesystem_type == "ntfs") {
    process->AddArgument(device_file);
    process->AddArgument(volume_name);
  }

  if (!process->Start()) {
    LOG(WARNING) << "Cannot start a process for renaming " << quote(device_path)
                 << " as filesystem " << quote(filesystem_type)
                 << " and volume name " << quote(volume_name);
    rename_process_.erase(device_path);
    return RenameError::kRenameProgramFailed;
  }

  process_reaper_->WatchForChild(
      FROM_HERE, process->pid(),
      base::BindOnce(&RenameManager::OnRenameProcessTerminated,
                     weak_ptr_factory_.GetWeakPtr(), device_path));
  return RenameError::kSuccess;
}

void RenameManager::OnRenameProcessTerminated(const std::string& device_path,
                                              const siginfo_t& info) {
  rename_process_.erase(device_path);
  RenameError error_type = RenameError::kUnknownError;
  switch (info.si_code) {
    case CLD_EXITED:
      if (info.si_status == 0) {
        error_type = RenameError::kSuccess;
        LOG(INFO) << "Process " << info.si_pid << " for renaming "
                  << quote(device_path) << " completed successfully";
      } else {
        error_type = RenameError::kRenameProgramFailed;
        LOG(ERROR) << "Process " << info.si_pid << " for renaming "
                   << quote(device_path) << " exited with a status "
                   << info.si_status;
      }
      break;

    case CLD_DUMPED:
    case CLD_KILLED:
      error_type = RenameError::kRenameProgramFailed;
      LOG(ERROR) << "Process " << info.si_pid << " for renaming "
                 << quote(device_path) << " killed by a signal "
                 << info.si_status;
      break;

    default:
      break;
  }

  if (observer_)
    observer_->OnRenameCompleted(device_path, error_type);
}

bool RenameManager::CanRename(const std::string& source_path) const {
  return base::StartsWith(source_path, "/sys/", base::CompareCase::SENSITIVE) ||
         base::StartsWith(source_path, "/devices/",
                          base::CompareCase::SENSITIVE) ||
         base::StartsWith(source_path, "/dev/", base::CompareCase::SENSITIVE);
}

}  // namespace cros_disks
