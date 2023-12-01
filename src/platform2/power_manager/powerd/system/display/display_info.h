// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_INFO_H_
#define POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_INFO_H_

#include <base/files/file_path.h>

namespace power_manager::system {

// Information about a connected display.
struct DisplayInfo {
 public:
  enum class ConnectorStatus {
    // The connector is definitely connected to a sink device, and can be
    // enabled.
    CONNECTED,
    // The connector's status could not be reliably detected. This happens when
    // probing would either cause flicker (like load-detection when the
    // connector is in use), or when connection status probes failed.
    UNKNOWN,
  };

  bool operator<(const DisplayInfo& rhs) const;
  bool operator==(const DisplayInfo& o) const;

  // Path to the directory in /sys representing the DRM device connected to this
  // display.
  base::FilePath drm_path;

  // Path to the I2C device in /dev that can be used to communicate with this
  // display.
  base::FilePath i2c_path;

  // Path to the parent device in /sys/devices.
  base::FilePath sys_path;

  // Connector status.
  ConnectorStatus connector_status = ConnectorStatus::UNKNOWN;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_DISPLAY_DISPLAY_INFO_H_
