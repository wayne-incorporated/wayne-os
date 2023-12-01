// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/thermal/device_thermal_state.h"

#include <string>

#include <base/logging.h>
#include <base/notreached.h>

#include "power_manager/proto_bindings/thermal.pb.h"

namespace power_manager::system {

std::string DeviceThermalStateToString(DeviceThermalState state) {
  switch (state) {
    case DeviceThermalState::kUnknown:
      return "Unknown";
    case DeviceThermalState::kNominal:
      return "Nominal";
    case DeviceThermalState::kFair:
      return "Fair";
    case DeviceThermalState::kSerious:
      return "Serious";
    case DeviceThermalState::kCritical:
      return "Critical";
  }
  NOTREACHED();
}

ThermalEvent::ThermalState DeviceThermalStateToProto(
    system::DeviceThermalState state) {
  switch (state) {
    case system::DeviceThermalState::kUnknown:
      return ThermalEvent_ThermalState_UNKNOWN;
    case system::DeviceThermalState::kNominal:
      return ThermalEvent_ThermalState_NOMINAL;
    case system::DeviceThermalState::kFair:
      return ThermalEvent_ThermalState_FAIR;
    case system::DeviceThermalState::kSerious:
      return ThermalEvent_ThermalState_SERIOUS;
    case system::DeviceThermalState::kCritical:
      return ThermalEvent_ThermalState_CRITICAL;
  }
  NOTREACHED();
}

}  // namespace power_manager::system
