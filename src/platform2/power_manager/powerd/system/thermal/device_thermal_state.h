// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_SYSTEM_THERMAL_DEVICE_THERMAL_STATE_H_
#define POWER_MANAGER_POWERD_SYSTEM_THERMAL_DEVICE_THERMAL_STATE_H_

#include <string>

#include "power_manager/proto_bindings/thermal.pb.h"

namespace power_manager::system {

enum class DeviceThermalState {
  // Thermal state is unknown.
  kUnknown,
  // The device's temperature-related conditions (thermals) are at an acceptable
  // level. There is no noticeable negative impact to the user.
  kNominal,
  //  Thermals are minimally elevated. On devices with fans, those fans may
  //  become active, audible, and distracting to the user. Energy usage is
  //  elevated, potentially reducing battery life.
  kFair,
  // Thermals are highly elevated. Fans are active, running at maximum speed,
  // audible, and distracting to the user. System performance may also be
  // impacted as the system begins enacting countermeasures to reduce thermals
  // to a more acceptable level.
  kSerious,
  // Thermals are significantly elevated. The device needs to cool down.
  kCritical,
};

std::string DeviceThermalStateToString(DeviceThermalState state);

ThermalEvent::ThermalState DeviceThermalStateToProto(
    system::DeviceThermalState state);

}  // namespace power_manager::system

#endif  // POWER_MANAGER_POWERD_SYSTEM_THERMAL_DEVICE_THERMAL_STATE_H_
