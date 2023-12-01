// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MEMS_SETUP_SENSOR_KIND_H_
#define MEMS_SETUP_SENSOR_KIND_H_

#include <string>

namespace mems_setup {

enum class SensorKind {
  ACCELEROMETER,
  GYROSCOPE,
  LIGHT,
  PROXIMITY,
  SYNC,
  MAGNETOMETER,
  LID_ANGLE,
  BAROMETER,
  HID_OTHERS,
  OTHERS,
};

std::string SensorKindToString(SensorKind kind);
// Used on EC stack sensors.
SensorKind SensorKindFromString(const std::string& name);

}  // namespace mems_setup

#endif  // MEMS_SETUP_SENSOR_KIND_H_
