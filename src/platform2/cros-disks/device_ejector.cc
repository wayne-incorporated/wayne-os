// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/device_ejector.h"

#include <linux/capability.h>

#include <memory>

#include <base/check.h>
#include <base/containers/contains.h>
#include <base/functional/bind.h>
#include <base/logging.h>

#include "cros-disks/quote.h"

namespace cros_disks {
namespace {

// Expected location of the 'eject' program.
const char kEjectProgram[] = "/usr/bin/eject";

}  // namespace

DeviceEjector::DeviceEjector(brillo::ProcessReaper* process_reaper)
    : process_reaper_(process_reaper), weak_ptr_factory_(this) {}

DeviceEjector::~DeviceEjector() = default;

bool DeviceEjector::Eject(const std::string& device_path) {
  CHECK(!device_path.empty()) << "Invalid device path";

  LOG(INFO) << "Eject device " << quote(device_path);
  if (base::Contains(eject_process_, device_path)) {
    LOG(WARNING) << "Device " << quote(device_path)
                 << " is already being ejected";
    return false;
  }

  SandboxedProcess* process = &eject_process_[device_path];
  process->SetNoNewPrivileges();
  process->NewIpcNamespace();
  process->NewNetworkNamespace();
  process->AddArgument(kEjectProgram);
  process->AddArgument(device_path);
  process->SetCapabilities(CAP_TO_MASK(CAP_SYS_ADMIN));

  // TODO(benchan): Set up a timeout to kill a hanging process.
  bool started = process->Start();
  if (started) {
    process_reaper_->WatchForChild(
        FROM_HERE, process->pid(),
        base::BindOnce(&DeviceEjector::OnEjectProcessTerminated,
                       weak_ptr_factory_.GetWeakPtr(), device_path));
  } else {
    eject_process_.erase(device_path);
    LOG(WARNING) << "Cannot eject media from device " << quote(device_path);
  }
  return started;
}

void DeviceEjector::OnEjectProcessTerminated(const std::string& device_path,
                                             const siginfo_t& info) {
  eject_process_.erase(device_path);
  switch (info.si_code) {
    case CLD_EXITED:
      if (info.si_status == 0) {
        LOG(INFO) << "Process " << info.si_pid << " for ejecting "
                  << quote(device_path) << " completed successfully";
      } else {
        LOG(ERROR) << "Process " << info.si_pid << " for ejecting "
                   << quote(device_path) << " exited with a status "
                   << info.si_status;
      }
      break;

    case CLD_DUMPED:
    case CLD_KILLED:
      LOG(ERROR) << "Process " << info.si_pid << " for ejecting "
                 << quote(device_path) << " killed by a signal "
                 << info.si_status;
      break;

    default:
      break;
  }
}

}  // namespace cros_disks
