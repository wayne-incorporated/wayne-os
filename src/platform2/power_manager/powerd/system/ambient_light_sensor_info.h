// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_INFO_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_INFO_H_

#include <string>

#include <base/files/file_path.h>

namespace power_manager::system {

// Information about a connected ambient light sensor.
struct AmbientLightSensorInfo {
 public:
  bool operator<(const AmbientLightSensorInfo& rhs) const;
  bool operator==(const AmbientLightSensorInfo& o) const;

  // Path to the directory in /sys representing the IIO device for the ambient
  // light sensor.
  base::FilePath iio_path;

  // IIO device name, used by sysfs implementation.
  std::string device;

  // Used by mojo implementation.
  int32_t id = -1;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_INFO_H_
