// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_POWERD_ADAPTER_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_POWERD_ADAPTER_H_

#include <base/observer_list_types.h>
#include <optional>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>
#include <power_manager/proto_bindings/suspend.pb.h>

namespace diagnostics {
namespace wilco {

constexpr char kPowerdPowerSupplyPropertiesFailedMessage[] =
    "Failed to get power supply properties from powerd.";

// Adapter for communication with powerd daemon.
class PowerdAdapter {
 public:
  // Observes general power events.
  class PowerObserver : public base::CheckedObserver {
   public:
    virtual ~PowerObserver() = default;

    virtual void OnPowerSupplyPollSignal(
        const power_manager::PowerSupplyProperties& power_supply) = 0;
    virtual void OnSuspendImminentSignal(
        const power_manager::SuspendImminent& suspend_imminent) = 0;
    virtual void OnDarkSuspendImminentSignal(
        const power_manager::SuspendImminent& suspend_imminent) = 0;
    virtual void OnSuspendDoneSignal(
        const power_manager::SuspendDone& suspend_done) = 0;
  };

  // Observes lid events.
  class LidObserver : public base::CheckedObserver {
   public:
    virtual ~LidObserver() = default;

    virtual void OnLidClosedSignal() = 0;
    virtual void OnLidOpenedSignal() = 0;
  };

  virtual ~PowerdAdapter() = default;

  virtual void AddPowerObserver(PowerObserver* observer) = 0;
  virtual void RemovePowerObserver(PowerObserver* observer) = 0;

  virtual void AddLidObserver(LidObserver* observer) = 0;
  virtual void RemoveLidObserver(LidObserver* observer) = 0;

  // Returns a PowerSupplyProperties proto from powerd on success. Will return a
  // std::nullopt if the powerd service is not available or the D-Bus response
  // cannot be parsed into the proto structure.
  virtual std::optional<power_manager::PowerSupplyProperties>
  GetPowerSupplyProperties() = 0;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_UTILS_SYSTEM_POWERD_ADAPTER_H_
