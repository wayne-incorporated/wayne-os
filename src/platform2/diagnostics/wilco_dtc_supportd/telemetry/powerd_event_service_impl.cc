// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/telemetry/powerd_event_service_impl.h"

#include <base/check.h>
#include <base/logging.h>

using PowerEventType =
    diagnostics::wilco::PowerdEventService::Observer::PowerEventType;

namespace diagnostics {
namespace wilco {

PowerdEventServiceImpl::PowerdEventServiceImpl(PowerdAdapter* powerd_adapter)
    : powerd_adapter_(powerd_adapter) {
  DCHECK(powerd_adapter_);
  powerd_adapter_->AddPowerObserver(this);
}

PowerdEventServiceImpl::~PowerdEventServiceImpl() {
  powerd_adapter_->RemovePowerObserver(this);
}

void PowerdEventServiceImpl::AddObserver(
    PowerdEventService::Observer* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void PowerdEventServiceImpl::RemoveObserver(
    PowerdEventService::Observer* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void PowerdEventServiceImpl::OnPowerSupplyPollSignal(
    const power_manager::PowerSupplyProperties& power_supply) {
  if (!power_supply.has_external_power()) {
    return;
  }

  PowerEventType event_type;
  switch (power_supply.external_power()) {
    case power_manager::PowerSupplyProperties::AC:
    case power_manager::PowerSupplyProperties::USB:
      event_type = PowerEventType::kAcInsert;
      break;
    case power_manager::PowerSupplyProperties::DISCONNECTED:
      event_type = PowerEventType::kAcRemove;
      break;
    default:
      LOG(ERROR) << "Unknown external power type: "
                 << power_supply.external_power();
      return;
  }

  // Do not send event if the previous AC event was the same.
  if (external_power_ac_event_.has_value() &&
      external_power_ac_event_.value() == event_type) {
    VLOG(2) << "Received the same AC event: " << static_cast<int>(event_type);
    return;
  }

  external_power_ac_event_ = event_type;
  for (auto& observer : observers_)
    observer.OnPowerdEvent(event_type);
}

void PowerdEventServiceImpl::OnSuspendImminentSignal(
    const power_manager::SuspendImminent& suspend_imminent) {
  OnAnySuspendImminentSignal(suspend_imminent);
}

void PowerdEventServiceImpl::OnDarkSuspendImminentSignal(
    const power_manager::SuspendImminent& suspend_imminent) {
  OnAnySuspendImminentSignal(suspend_imminent);
}

void PowerdEventServiceImpl::OnSuspendDoneSignal(
    const power_manager::SuspendDone& suspend_done) {
  for (auto& observer : observers_)
    observer.OnPowerdEvent(PowerEventType::kOsResume);
}

void PowerdEventServiceImpl::OnAnySuspendImminentSignal(
    const power_manager::SuspendImminent& suspend_imminent) {
  for (auto& observer : observers_)
    observer.OnPowerdEvent(PowerEventType::kOsSuspend);
}

}  // namespace wilco
}  // namespace diagnostics
