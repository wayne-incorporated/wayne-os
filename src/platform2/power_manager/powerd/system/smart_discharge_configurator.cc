// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/smart_discharge_configurator.h"

#include <fcntl.h>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <libec/smart_discharge_command.h>

namespace power_manager::system {

void ConfigureSmartDischarge(int64_t to_zero_hr,
                             int64_t cutoff_ua,
                             int64_t hibernate_ua) {
  if (to_zero_hr < 0 || cutoff_ua < 0 || hibernate_ua < 0)
    return;

  base::ScopedFD cros_ec_fd = base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));
  if (!cros_ec_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << ec::kCrosEcPath;
    return;
  }

  // TODO(b/265492733): Move to EcCommandFactory to allow mocking for unittests.
  ec::SmartDischargeCommand cmd(to_zero_hr, cutoff_ua, hibernate_ua);
  if (!cmd.Run(cros_ec_fd.get())) {
    LOG(ERROR) << "Failed to set Smart Discharge to " << to_zero_hr
               << " hrs to zero, cutoff power " << cutoff_ua
               << " uA, hibernate power " << hibernate_ua << " uA";
    return;
  }
  LOG(INFO) << "Smart Discharge set to " << cmd.HoursToZero()
            << " hrs to zero, cutoff power " << cmd.CutoffCurrentMicroAmps()
            << " uA, hibernate power " << cmd.HibernationCurrentMicroAmps()
            << " uA, cutoff threshold "
            << cmd.BatteryCutoffThresholdMilliAmpHours()
            << " mAh, stay-up threshold "
            << cmd.ECStayupThresholdMilliAmpHours() << " mAh";
}

}  // namespace power_manager::system
