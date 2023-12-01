// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secanomalyd/system_context.h"

#include <ios>  // std::boolalpha
#include <map>
#include <string>

#include <sys/syscall.h>

#include "secanomalyd/landlock.h"
#include "secanomalyd/mount_entry.h"

SystemContext::SystemContext(SessionManagerProxyInterface* session_manager)
    : session_manager_{session_manager} {
  std::ignore = UpdateLoggedInState();
  UpdateLandlockState();
}

void SystemContext::Refresh() {
  std::ignore = UpdateLoggedInState();
  UpdateKnownMountsState();
}

bool SystemContext::UpdateLoggedInState() {
  brillo::ErrorPtr error;
  std::map<std::string, std::string> sessions;
  session_manager_->RetrieveActiveSessions(&sessions, &error);

  if (error) {
    LOG(ERROR) << "Error making D-Bus proxy call to interface "
               << "'" << session_manager_->GetObjectPath().value()
               << "': " << error->GetMessage();
    logged_in_ = false;
    return false;
  }
  logged_in_ = sessions.size() > 0;
  VLOG(1) << "logged_in_ -> " << std::boolalpha << logged_in_;
  return true;
}

void SystemContext::UpdateLandlockState() {
  int landlock_version =
      landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
  if (landlock_version <= 0) {
    const int err = errno;
    switch (err) {
      case ENOSYS: {
        LOG(WARNING) << "Landlock is not supported by the kernel.";
        landlock_state_ = LandlockState::kNotSupported;
        break;
      }
      case EOPNOTSUPP: {
        LOG(WARNING)
            << "Landlock is supported by the kernel but disabled at boot time.";
        landlock_state_ = LandlockState::kDisabled;
        break;
      }
      default: {
        LOG(WARNING) << "Could not determine Landlock state.";
        landlock_state_ = LandlockState::kUnknown;
        break;
      }
    }
  } else {
    VLOG(1) << "Landlock is enabled; Version " << landlock_version;
    landlock_state_ = LandlockState::kEnabled;
  }
}

void SystemContext::UpdateKnownMountsState() {
  previous_known_mounts_.clear();
  previous_known_mounts_.merge(current_known_mounts_);
}

bool SystemContext::IsMountPersistent(const base::FilePath& known_mount) const {
  return (previous_known_mounts_.count(known_mount) == 1);
}

void SystemContext::RecordKnownMountObservation(
    const base::FilePath& known_mount) {
  // Ensures `known_mount` is indeed a predefined known mount.
  if (secanomalyd::kKnownMounts.count(known_mount) == 0) {
    return;
  }
  current_known_mounts_.insert(known_mount);
}
