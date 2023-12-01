// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_UPDATER_CROS_FP_UPDATER_H_
#define BIOD_UPDATER_CROS_FP_UPDATER_H_

#include <optional>
#include <string>

#include <base/files/file_path.h>
#include <brillo/enum_flags.h>
#include <chromeos/ec/ec_commands.h>
#include <cros_config/cros_config_interface.h>

#include "base/command_line.h"
#include "base/time/time.h"
#include "biod/biod_system.h"
#include "biod/cros_fp_device.h"
#include "biod/cros_fp_firmware.h"
#include "biod/updater/update_reason.h"
#include "biod/updater/update_status.h"

namespace biod {

// Imposes a timeout of duration timeout_time to an input command. Returns the
// boolean status of the command in addition to the string output.
bool GetAppOutputAndErrorWithTimeout(const base::CommandLine& cmd_input,
                                     const base::TimeDelta& delta,
                                     std::string* output);

// These utilities should be absorbed by CrosFpDevice.
// This is a temporary holding place until they can be absorbed.
class CrosFpDeviceUpdate {
 public:
  virtual ~CrosFpDeviceUpdate() = default;
  virtual std::optional<ec::CrosFpDeviceInterface::EcVersion> GetVersion()
      const;
  virtual bool IsFlashProtectEnabled(bool* status) const;
  virtual bool Flash(const CrosFpFirmware& fw, enum ec_image image) const;
  static std::string EcCurrentImageToString(enum ec_image image);
};

// CrosFpBootUpdateCtrl holds the interfaces for the
// external boot-time environment.
class CrosFpBootUpdateCtrl {
 public:
  virtual ~CrosFpBootUpdateCtrl() = default;
  virtual bool TriggerBootUpdateSplash() const;
  virtual bool ScheduleReboot() const;
};

namespace updater {

struct UpdateResult {
  UpdateStatus status;
  UpdateReason reason;
};

UpdateResult DoUpdate(const CrosFpDeviceUpdate& ec_dev,
                      const CrosFpBootUpdateCtrl& boot_ctrl,
                      const CrosFpFirmware& fw,
                      const BiodSystem& system,
                      brillo::CrosConfigInterface* cros_config);

}  // namespace updater
}  // namespace biod

#endif  // BIOD_UPDATER_CROS_FP_UPDATER_H_
