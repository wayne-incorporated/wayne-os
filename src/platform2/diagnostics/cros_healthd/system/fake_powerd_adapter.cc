// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/system/fake_powerd_adapter.h"

#include <optional>

namespace diagnostics {

FakePowerdAdapter::FakePowerdAdapter() = default;
FakePowerdAdapter::~FakePowerdAdapter() = default;

// PowerdAdapter overrides:
std::optional<power_manager::PowerSupplyProperties>
FakePowerdAdapter::GetPowerSupplyProperties() {
  return power_supply_properties_;
}

void FakePowerdAdapter::SetPowerSupplyProperties(
    std::optional<power_manager::PowerSupplyProperties> properties) {
  power_supply_properties_ = properties;
}

}  // namespace diagnostics
