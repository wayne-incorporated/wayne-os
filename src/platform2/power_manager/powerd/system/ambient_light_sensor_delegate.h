// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_DELEGATE_H_
#define POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_DELEGATE_H_

#include <map>
#include <optional>

#include <base/files/file_path.h>
#include <base/functional/callback.h>

namespace power_manager::system {

enum class ChannelType {
  X,
  Y,
  Z,
};

const struct ColorChannelInfo {
  ChannelType type;
  const char* rgb_name;
  const char* xyz_name;
} kColorChannelConfig[] = {
    {ChannelType::X, "red", "x"},
    {ChannelType::Y, "green", "y"},
    {ChannelType::Z, "blue", "z"},
};

enum class SensorLocation {
  UNKNOWN,
  BASE,
  LID,
};

class AmbientLightSensorDelegate {
 public:
  // |readings[ChannelType::X]|: red color reading value.
  // |readings[ChannelType::Y]|: green color reading value.
  // |readings[ChannelType::Z]|: blue color reading value.
  // Returns std::nullopt if the color temperature is unavailable.
  static std::optional<int> CalculateColorTemperature(
      const std::map<ChannelType, int>& readings);

  AmbientLightSensorDelegate() = default;
  AmbientLightSensorDelegate(const AmbientLightSensorDelegate&) = delete;
  AmbientLightSensorDelegate& operator=(const AmbientLightSensorDelegate&) =
      delete;
  virtual ~AmbientLightSensorDelegate() = default;

  virtual bool IsColorSensor() const = 0;
  virtual base::FilePath GetIlluminancePath() const = 0;

  void SetLuxCallback(
      base::RepeatingCallback<void(std::optional<int>, std::optional<int>)>
          set_lux_callback);

 protected:
  base::RepeatingCallback<void(std::optional<int>, std::optional<int>)>
      set_lux_callback_;
};

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_AMBIENT_LIGHT_SENSOR_DELEGATE_H_
