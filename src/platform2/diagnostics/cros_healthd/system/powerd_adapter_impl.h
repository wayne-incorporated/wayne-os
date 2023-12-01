// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_SYSTEM_POWERD_ADAPTER_IMPL_H_
#define DIAGNOSTICS_CROS_HEALTHD_SYSTEM_POWERD_ADAPTER_IMPL_H_

#include <optional>

#include <base/memory/weak_ptr.h>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>

#include "diagnostics/cros_healthd/system/powerd_adapter.h"

namespace org {
namespace chromium {
class PowerManagerProxyInterface;
}  // namespace chromium
}  // namespace org

namespace diagnostics {

// PowerdAdapter interface implementation that communicates with powerd.
class PowerdAdapterImpl : public PowerdAdapter {
 public:
  explicit PowerdAdapterImpl(
      org::chromium::PowerManagerProxyInterface* power_manager_proxy);
  PowerdAdapterImpl(const PowerdAdapterImpl&) = delete;
  PowerdAdapterImpl& operator=(const PowerdAdapterImpl&) = delete;
  ~PowerdAdapterImpl() override;

  // PowerdAdapter overrides:
  std::optional<power_manager::PowerSupplyProperties> GetPowerSupplyProperties()
      override;

 private:
  // Unowned pointer that should outlive this instance.
  org::chromium::PowerManagerProxyInterface* const power_manager_proxy_ =
      nullptr;

  base::WeakPtrFactory<PowerdAdapterImpl> weak_ptr_factory_{this};
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_SYSTEM_POWERD_ADAPTER_IMPL_H_
