// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/system/powerd_adapter_impl.h"

#include <optional>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <brillo/errors/error.h>
#include <power_manager/dbus-proxies.h>

namespace diagnostics {

namespace {

// The maximum amount of time to wait for a powerd response.
constexpr base::TimeDelta kPowerManagerDBusTimeout = base::Seconds(3);

}  // namespace

PowerdAdapterImpl::PowerdAdapterImpl(
    org::chromium::PowerManagerProxyInterface* power_manager_proxy)
    : power_manager_proxy_(power_manager_proxy) {
  CHECK(power_manager_proxy_);
}

PowerdAdapterImpl::~PowerdAdapterImpl() = default;

std::optional<power_manager::PowerSupplyProperties>
PowerdAdapterImpl::GetPowerSupplyProperties() {
  std::vector<uint8_t> out_serialized_proto;
  brillo::ErrorPtr error;
  if (!power_manager_proxy_->GetPowerSupplyProperties(
          &out_serialized_proto, &error,
          kPowerManagerDBusTimeout.InMilliseconds())) {
    LOG(ERROR) << "Failed to GetPowerSupplyProperties";
    return std::nullopt;
  }

  power_manager::PowerSupplyProperties power_supply_proto;
  if (!power_supply_proto.ParseFromArray(out_serialized_proto.data(),
                                         out_serialized_proto.size())) {
    LOG(ERROR) << "Could not successfully read PowerSupplyProperties protobuf";
    return std::nullopt;
  }

  return power_supply_proto;
}

}  // namespace diagnostics
