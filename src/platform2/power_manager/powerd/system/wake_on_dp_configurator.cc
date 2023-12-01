// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/wake_on_dp_configurator.h"

#include <fcntl.h>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <libec/get_mkbp_wake_mask_command.h>
#include <libec/set_mkbp_wake_mask_command.h>

namespace power_manager::system {
namespace {

bool GetMkbpWakeMask(const base::ScopedFD& cros_ec_fd,
                     uint32_t* wake_mask_out) {
  DCHECK(cros_ec_fd.is_valid());
  DCHECK(wake_mask_out);
  if (cros_ec_fd.get() < 0)
    return false;

  // TODO(b/265492733): Move to EcCommandFactory to allow mocking for unittests.
  ec::GetMkbpWakeMaskEventCommand cmd;
  if (!cmd.Run(cros_ec_fd.get())) {
    LOG(ERROR) << "Failed to get current MKBP wake mask. Result : "
               << cmd.Result();
    return false;
  }

  *wake_mask_out = cmd.GetWakeMask();

  return true;
}

bool SetMkbpWakeMask(const base::ScopedFD& cros_ec_fd, uint32_t wake_mask) {
  DCHECK(cros_ec_fd.is_valid());
  if (cros_ec_fd.get() < 0)
    return false;

  // TODO(b/265492733): Move to EcCommandFactory to allow mocking for unittests.
  ec::SetMkbpWakeMaskEventCommand cmd(wake_mask);
  if (!cmd.Run(cros_ec_fd.get())) {
    LOG(ERROR) << "Failed to set new MKBP wake mask to '0x" << std::hex
               << wake_mask << "' Result: " << std::dec << cmd.Result();
    return false;
  }
  return true;
}

}  // namespace

void ConfigureWakeOnDp(bool enable) {
  uint32_t wake_mask;
  base::ScopedFD cros_ec_fd = base::ScopedFD(open(ec::kCrosEcPath, O_RDWR));

  if (!cros_ec_fd.is_valid()) {
    PLOG(ERROR) << "Failed to open " << ec::kCrosEcPath;
    return;
  }

  if (!GetMkbpWakeMask(cros_ec_fd, &wake_mask))
    return;

  if (enable)
    wake_mask |= (1 << EC_MKBP_EVENT_DP_ALT_MODE_ENTERED);
  else
    wake_mask &= ~(1 << EC_MKBP_EVENT_DP_ALT_MODE_ENTERED);

  if (SetMkbpWakeMask(cros_ec_fd, wake_mask))
    LOG(INFO) << "Wake on dp is " << (enable ? "enabled" : "disabled");
}

}  // namespace power_manager::system
