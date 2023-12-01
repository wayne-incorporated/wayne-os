// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <base/notreached.h>

#include <libmems/common_types.h>

#include "mems_setup/sensor_kind.h"

namespace mems_setup {

namespace {
constexpr char kOthersName[] = "";

constexpr char kAccelDeviceName[] = "cros-ec-accel";
constexpr char kGyroDeviceName[] = "cros-ec-gyro";
constexpr char kLightDeviceName[] = "cros-ec-light";
constexpr char kAlsDeviceName[] = "acpi-als";
constexpr char kSyncDeviceName[] = "cros-ec-sync";
constexpr char kMagnDeviceName[] = "cros-ec-mag";
constexpr char kLidAngleDeviceName[] = "cros-ec-lid-angle";
constexpr char kBaroDeviceName[] = "cros-ec-baro";

constexpr char kProxDeviceNames[][23] = {
    "cros-ec-activity", "cros-ec-prox", "sx9310", "sx9311",
    "sx9324",           "sx932x",       "sx9360", "cros-ec-mkbp-proximity"};

constexpr char kHidDeviceNames[][13] = {
    "accel_3d",    "gyro_3d",  "magn_3d",     "als",
    "temperature", "incli_3d", "dev_rotation"};
}  // namespace

std::string SensorKindToString(SensorKind kind) {
  switch (kind) {
    case SensorKind::ACCELEROMETER:
      return libmems::kAccelName;
    case SensorKind::GYROSCOPE:
      return libmems::kGyroName;
    case SensorKind::LIGHT:
      return libmems::kLightName;
    case SensorKind::SYNC:
      return libmems::kSyncName;
    case SensorKind::MAGNETOMETER:
      return libmems::kMagnName;
    case SensorKind::LID_ANGLE:
      return libmems::kLidAngleName;
    case SensorKind::PROXIMITY:
      return libmems::kProxName;
    case SensorKind::BAROMETER:
      return libmems::kBaroName;
    case SensorKind::HID_OTHERS:
    case SensorKind::OTHERS:
      return kOthersName;  // Shouldn't be used
  }

  NOTREACHED();
}

SensorKind SensorKindFromString(const std::string& name) {
  if (name == kAccelDeviceName)
    return SensorKind::ACCELEROMETER;
  if (name == kGyroDeviceName)
    return SensorKind::GYROSCOPE;
  if (name == kLightDeviceName || name == kAlsDeviceName)
    return SensorKind::LIGHT;
  if (name == kSyncDeviceName)
    return SensorKind::SYNC;
  if (name == kMagnDeviceName)
    return SensorKind::MAGNETOMETER;
  if (name == kLidAngleDeviceName)
    return SensorKind::LID_ANGLE;
  if (name == kBaroDeviceName)
    return SensorKind::BAROMETER;

  for (const auto& prox_device_name : kProxDeviceNames) {
    if (name.compare(prox_device_name) == 0)
      return SensorKind::PROXIMITY;
  }

  for (const auto& hid_device_name : kHidDeviceNames) {
    if (name.compare(hid_device_name) == 0)
      return SensorKind::HID_OTHERS;
  }

  return SensorKind::OTHERS;
}

}  // namespace mems_setup
