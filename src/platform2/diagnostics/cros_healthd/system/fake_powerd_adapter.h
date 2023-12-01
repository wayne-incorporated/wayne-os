// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_POWERD_ADAPTER_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_POWERD_ADAPTER_H_

#include <optional>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>

#include "diagnostics/cros_healthd/system/powerd_adapter.h"

namespace diagnostics {

class FakePowerdAdapter : public PowerdAdapter {
 public:
  FakePowerdAdapter();
  FakePowerdAdapter(const FakePowerdAdapter&) = delete;
  FakePowerdAdapter& operator=(const FakePowerdAdapter&) = delete;
  ~FakePowerdAdapter() override;

  // PowerdAdapter overrides:
  std::optional<power_manager::PowerSupplyProperties> GetPowerSupplyProperties()
      override;

  void SetPowerSupplyProperties(
      std::optional<power_manager::PowerSupplyProperties> properties);

 private:
  std::optional<power_manager::PowerSupplyProperties> power_supply_properties_;
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_FAKE_POWERD_ADAPTER_H_
