// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_POWERD_EVENT_SERVICE_IMPL_H_
#define DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_POWERD_EVENT_SERVICE_IMPL_H_

#include <base/observer_list.h>
#include <optional>
#include <power_manager/proto_bindings/power_supply_properties.pb.h>
#include <power_manager/proto_bindings/suspend.pb.h>

#include "diagnostics/wilco_dtc_supportd/telemetry/powerd_event_service.h"
#include "diagnostics/wilco_dtc_supportd/utils/system/powerd_adapter.h"

namespace diagnostics {
namespace wilco {

// PowerdEventService interface implementation that obrerves events from
// PowerdAdapter, parses proto messages and notifes it's observers about power
// events.
class PowerdEventServiceImpl : public PowerdEventService,
                               public PowerdAdapter::PowerObserver {
 public:
  explicit PowerdEventServiceImpl(PowerdAdapter* powerd_adapter);
  PowerdEventServiceImpl(const PowerdEventServiceImpl&) = delete;
  PowerdEventServiceImpl& operator=(const PowerdEventServiceImpl&) = delete;

  ~PowerdEventServiceImpl() override;

  // PowerdEventService overrides:
  void AddObserver(PowerdEventService::Observer* observer) override;
  void RemoveObserver(PowerdEventService::Observer* observer) override;

 private:
  // PowerdAdapter::Observer overrides:
  void OnPowerSupplyPollSignal(
      const power_manager::PowerSupplyProperties& power_supply) override;
  void OnSuspendImminentSignal(
      const power_manager::SuspendImminent& suspend_imminent) override;
  void OnDarkSuspendImminentSignal(
      const power_manager::SuspendImminent& suspend_imminent) override;
  void OnSuspendDoneSignal(
      const power_manager::SuspendDone& suspend_done) override;

  void OnAnySuspendImminentSignal(
      const power_manager::SuspendImminent& suspend_imminent);

  base::ObserverList<PowerdEventService::Observer> observers_;

  // Not owned.
  PowerdAdapter* powerd_adapter_;

  // Latest external power AC event since powerd sent PowerSupplyPollSignal
  // (updates every 30 seconds or when something changes in power supply).
  std::optional<PowerdEventService::Observer::PowerEventType>
      external_power_ac_event_;
};

}  // namespace wilco
}  // namespace diagnostics

#endif  // DIAGNOSTICS_WILCO_DTC_SUPPORTD_TELEMETRY_POWERD_EVENT_SERVICE_IMPL_H_
