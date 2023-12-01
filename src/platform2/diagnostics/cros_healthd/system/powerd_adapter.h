// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_POWERD_ADAPTER_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_POWERD_ADAPTER_H_

#include <optional>

#include <power_manager/proto_bindings/power_supply_properties.pb.h>

namespace diagnostics {

constexpr char kPowerdPowerSupplyPropertiesFailedMessage[] =
    "Failed to get power supply properties from powerd.";

// Adapter for communication with powerd daemon.
class PowerdAdapter {
 public:
  virtual ~PowerdAdapter() = default;

  // Returns a PowerSupplyProperties proto from powerd on success. Will return a
  // std::nullopt if the powerd service is not available or the D-Bus response
  // cannot be parsed into the proto structure.
  virtual std::optional<power_manager::PowerSupplyProperties>
  GetPowerSupplyProperties() = 0;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_POWERD_ADAPTER_H_
