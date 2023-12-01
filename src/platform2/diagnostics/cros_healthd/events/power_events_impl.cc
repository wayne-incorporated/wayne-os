// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/events/power_events_impl.h"

#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <power_manager/dbus-proxies.h>

namespace {

namespace mojom = ::ash::cros_healthd::mojom;

// Handles the result of an attempt to connect to a D-Bus signal.
void HandleSignalConnected(const std::string& interface,
                           const std::string& signal,
                           bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to connect to signal " << interface << "." << signal;
    return;
  }
  VLOG(2) << "Successfully connected to D-Bus signal " << interface << "."
          << signal;
}

}  // namespace

namespace diagnostics {

PowerEventsImpl::PowerEventsImpl(Context* context)
    : context_(context), weak_ptr_factory_(this) {
  DCHECK(context_);

  context_->power_manager_proxy()->RegisterPowerSupplyPollSignalHandler(
      base::BindRepeating(&PowerEventsImpl::OnPowerSupplyPollSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
  context_->power_manager_proxy()->RegisterSuspendImminentSignalHandler(
      base::BindRepeating(&PowerEventsImpl::OnSuspendImminentSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
  context_->power_manager_proxy()->RegisterDarkSuspendImminentSignalHandler(
      base::BindRepeating(&PowerEventsImpl::OnDarkSuspendImminentSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
  context_->power_manager_proxy()->RegisterSuspendDoneSignalHandler(
      base::BindRepeating(&PowerEventsImpl::OnSuspendDoneSignal,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
}

void PowerEventsImpl::AddObserver(
    mojo::PendingRemote<mojom::EventObserver> observer) {
  observers_.Add(std::move(observer));
}

void PowerEventsImpl::AddObserver(
    mojo::PendingRemote<mojom::CrosHealthdPowerObserver> observer) {
  deprecated_observers_.Add(std::move(observer));
}

void PowerEventsImpl::OnPowerSupplyPollSignal(
    const std::vector<uint8_t>& signal) {
  power_manager::PowerSupplyProperties power_supply;
  if (signal.empty() ||
      !power_supply.ParseFromArray(&signal.front(), signal.size())) {
    LOG(ERROR) << "Unable to parse PowerSupplyPoll signal";
    return;
  }

  if (!power_supply.has_external_power())
    return;

  PowerEventType event_type;
  switch (power_supply.external_power()) {
    case power_manager::PowerSupplyProperties::AC:  // FALLTHROUGH
    case power_manager::PowerSupplyProperties::USB:
      event_type = PowerEventType::kAcInserted;
      break;
    case power_manager::PowerSupplyProperties::DISCONNECTED:
      event_type = PowerEventType::kAcRemoved;
      break;
    default:
      LOG(ERROR) << "Unknown external power type: "
                 << power_supply.external_power();
      return;
  }

  // Do not send an event if the previous AC event was the same.
  if (external_power_ac_event_.has_value() &&
      external_power_ac_event_.value() == event_type) {
    VLOG(2) << "Received the same AC event: " << static_cast<int>(event_type);
    return;
  }

  external_power_ac_event_ = event_type;
  mojom::PowerEventInfo info;
  for (auto& observer : observers_) {
    switch (event_type) {
      case PowerEventType::kAcInserted:
        info.state = mojom::PowerEventInfo::State::kAcInserted;
        break;
      case PowerEventType::kAcRemoved:
        info.state = mojom::PowerEventInfo::State::kAcRemoved;
        break;
    }
    observer->OnEvent(mojom::EventInfo::NewPowerEventInfo(info.Clone()));
  }
  for (auto& observer : deprecated_observers_) {
    switch (event_type) {
      case PowerEventType::kAcInserted:
        observer->OnAcInserted();
        break;
      case PowerEventType::kAcRemoved:
        observer->OnAcRemoved();
        break;
    }
  }
}

void PowerEventsImpl::OnSuspendImminentSignal(
    const std::vector<uint8_t>& /* signal */) {
  OnAnySuspendImminentSignal();
}

void PowerEventsImpl::OnDarkSuspendImminentSignal(
    const std::vector<uint8_t>& /* signal */) {
  OnAnySuspendImminentSignal();
}

void PowerEventsImpl::OnSuspendDoneSignal(
    const std::vector<uint8_t>& /* signal */) {
  mojom::PowerEventInfo info;
  info.state = mojom::PowerEventInfo::State::kOsResume;
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewPowerEventInfo(info.Clone()));
  for (auto& observer : deprecated_observers_)
    observer->OnOsResume();
}

void PowerEventsImpl::OnAnySuspendImminentSignal() {
  mojom::PowerEventInfo info;
  info.state = mojom::PowerEventInfo::State::kOsSuspend;
  for (auto& observer : observers_)
    observer->OnEvent(mojom::EventInfo::NewPowerEventInfo(info.Clone()));
  for (auto& observer : deprecated_observers_)
    observer->OnOsSuspend();
}

}  // namespace diagnostics
