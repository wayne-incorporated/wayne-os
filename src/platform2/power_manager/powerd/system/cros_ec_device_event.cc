// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/cros_ec_device_event.h"

#include <fcntl.h>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <libec/device_event_command.h>

namespace power_manager::system {

// The current implementation does read->set->write. This isn't ideal because
// the enable mask can be modified between the read and the write by anything
// else. This is a limitation of EC_DEVICE_EVENT_PARAM_SET_ENABLED_EVENTS.
// We should instead make EC support EC_DEVICE_EVENT_PARAM_ENABLE_EVENTS,
// which allows event masks to be set and unset atomically.
void EnableCrosEcDeviceEvent(enum ec_device_event event, bool enable) {
  static bool cmd_supported = true;

  if (!cmd_supported)
    return;

  base::ScopedFD ec_fd = base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));

  if (!ec_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << ec::kCrosEcPath;
    return;
  }

  // TODO(b/265492733): Move to EcCommandFactory to allow mocking for unittests.
  ec::DeviceEventCommand get_cmd(/* clear_pending_events= */ false);
  if (!get_cmd.Run(ec_fd.get())) {
    // Expected on boards with device event disabled. Print warning only once.
    LOG(WARNING) << "Failed to get CrOS EC device event mask";
    cmd_supported = false;
    return;
  }

  if (get_cmd.IsEnabled(event) == enable) {
    LOG(INFO) << "CrOS EC device event is already "
              << (enable ? "enabled" : "disabled") << " for " << event;
    return;
  }

  ec::DeviceEventCommand set_cmd(event, enable, get_cmd.GetMask());
  if (!set_cmd.Run(ec_fd.get())) {
    LOG(ERROR) << "Failed to set CrOS EC device event for " << event;
    return;
  }

  if (set_cmd.IsEnabled(event) != enable) {
    LOG(ERROR) << "Failed to " << (enable ? "enable" : "disable")
               << " CrOS EC device event for " << event;
    return;
  }

  LOG(INFO) << "CrOS EC device event is " << (enable ? "enabled" : "disabled")
            << " for " << event;
}

}  // namespace power_manager::system
