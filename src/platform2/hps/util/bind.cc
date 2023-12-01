// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Bind/unbind the HPS kernel module. Unbinding the kernel driver makes the i2c
 * device accessible to userspace and ensures it remains powered up.
 */

#include <base/command_line.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>

#include "hps/util/command.h"

namespace {

/// Path to the sysfs node of the HPS kernel driver.
constexpr char kHpsI2cSysfsPath[] = "/sys/bus/i2c/drivers/cros-hps";

// The i2c device id for HPS.
constexpr char kHpsI2cDeviceId[] = "i2c-GOOG0020:00";

int BindControl(std::unique_ptr<hps::HPS> hps,
                const base::CommandLine::StringVector& args) {
  base::FilePath ctrl_path(kHpsI2cSysfsPath);
  if (!base::PathExists(ctrl_path)) {
    PLOG(ERROR) << "Kernel driver not present at " << ctrl_path;
    return 1;
  }
  ctrl_path = ctrl_path.Append(args[0]);
  base::File ctrl_file(ctrl_path,
                       base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  int ret =
      base::WriteFile(ctrl_path, kHpsI2cDeviceId, strlen(kHpsI2cDeviceId));
  if (ret < 0) {
    PLOG(ERROR) << "Failed to write to " << ctrl_path;
    return 1;
  }
  return 0;
}

Command bindCmd("bind",
                "bind - "
                "Enable the HPS kernel driver",
                BindControl);
Command unbindCmd("unbind",
                  "unbind - "
                  "Disable the HPS kernel driver, freeing the I2C interface",
                  BindControl);

}  // namespace
