// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/wilco_dtc_supportd/utils/system/powerd_adapter_impl.h"

#include <optional>
#include <string>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <dbus/object_proxy.h>
#include <dbus/message.h>
#include <dbus/power_manager/dbus-constants.h>
#include <base/time/time.h>

namespace diagnostics {
namespace wilco {

namespace {

// The maximum amount of time to wait for a powerd response.
constexpr base::TimeDelta kPowerManagerDBusTimeout = base::Seconds(3);

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

PowerdAdapterImpl::PowerdAdapterImpl(const scoped_refptr<dbus::Bus>& bus)
    : bus_proxy_(bus->GetObjectProxy(
          power_manager::kPowerManagerServiceName,
          dbus::ObjectPath(power_manager::kPowerManagerServicePath))),
      weak_ptr_factory_(this) {
  DCHECK(bus);
  DCHECK(bus_proxy_);

  bus_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface,
      power_manager::kPowerSupplyPollSignal,
      base::BindRepeating(&PowerdAdapterImpl::HandlePowerSupplyPoll,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
  bus_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface,
      power_manager::kSuspendImminentSignal,
      base::BindRepeating(&PowerdAdapterImpl::HandleSuspendImminent,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
  bus_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface,
      power_manager::kDarkSuspendImminentSignal,
      base::BindRepeating(&PowerdAdapterImpl::HandleDarkSuspendImminent,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
  bus_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface, power_manager::kSuspendDoneSignal,
      base::BindRepeating(&PowerdAdapterImpl::HandleSuspendDone,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
  bus_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface, power_manager::kLidClosedSignal,
      base::BindRepeating(&PowerdAdapterImpl::HandleLidClosed,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
  bus_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface, power_manager::kLidOpenedSignal,
      base::BindRepeating(&PowerdAdapterImpl::HandleLidOpened,
                          weak_ptr_factory_.GetWeakPtr()),
      base::BindOnce(&HandleSignalConnected));
}

PowerdAdapterImpl::~PowerdAdapterImpl() = default;

void PowerdAdapterImpl::AddPowerObserver(PowerObserver* observer) {
  DCHECK(observer);
  power_observers_.AddObserver(observer);
}

void PowerdAdapterImpl::RemovePowerObserver(PowerObserver* observer) {
  DCHECK(observer);
  power_observers_.RemoveObserver(observer);
}

void PowerdAdapterImpl::AddLidObserver(LidObserver* observer) {
  DCHECK(observer);
  lid_observers_.AddObserver(observer);
}

void PowerdAdapterImpl::RemoveLidObserver(LidObserver* observer) {
  DCHECK(observer);
  lid_observers_.RemoveObserver(observer);
}

std::optional<power_manager::PowerSupplyProperties>
PowerdAdapterImpl::GetPowerSupplyProperties() {
  dbus::MethodCall method_call(power_manager::kPowerManagerInterface,
                               power_manager::kGetPowerSupplyPropertiesMethod);
  auto response = bus_proxy_->CallMethodAndBlock(
      &method_call, kPowerManagerDBusTimeout.InMilliseconds());

  if (!response) {
    LOG(ERROR) << "Failed to call powerd D-Bus method: "
               << power_manager::kGetPowerSupplyPropertiesMethod;
    return std::nullopt;
  }

  dbus::MessageReader reader(response.get());
  power_manager::PowerSupplyProperties power_supply_proto;
  if (!reader.PopArrayOfBytesAsProto(&power_supply_proto)) {
    LOG(ERROR) << "Could not successfully read PowerSupplyProperties protobuf";
    return std::nullopt;
  }

  return power_supply_proto;
}

void PowerdAdapterImpl::HandlePowerSupplyPoll(dbus::Signal* signal) {
  DCHECK(signal);

  dbus::MessageReader reader(signal);
  power_manager::PowerSupplyProperties proto;
  if (!reader.PopArrayOfBytesAsProto(&proto)) {
    LOG(ERROR) << "Unable to parse PowerSupplyPoll signal";
    return;
  }

  for (auto& observer : power_observers_)
    observer.OnPowerSupplyPollSignal(proto);
}

void PowerdAdapterImpl::HandleSuspendImminent(dbus::Signal* signal) {
  DCHECK(signal);

  dbus::MessageReader reader(signal);
  power_manager::SuspendImminent proto;
  if (!reader.PopArrayOfBytesAsProto(&proto)) {
    LOG(ERROR) << "Unable to parse SuspendImminent signal";
    return;
  }

  for (auto& observer : power_observers_)
    observer.OnSuspendImminentSignal(proto);
}

void PowerdAdapterImpl::HandleDarkSuspendImminent(dbus::Signal* signal) {
  DCHECK(signal);

  dbus::MessageReader reader(signal);
  power_manager::SuspendImminent proto;
  if (!reader.PopArrayOfBytesAsProto(&proto)) {
    LOG(ERROR) << "Unable to parse DarkSuspendImminent signal";
    return;
  }

  for (auto& observer : power_observers_)
    observer.OnDarkSuspendImminentSignal(proto);
}

void PowerdAdapterImpl::HandleSuspendDone(dbus::Signal* signal) {
  DCHECK(signal);

  dbus::MessageReader reader(signal);
  power_manager::SuspendDone proto;
  if (!reader.PopArrayOfBytesAsProto(&proto)) {
    LOG(ERROR) << "Unable to parse SuspendDone signal";
    return;
  }

  for (auto& observer : power_observers_)
    observer.OnSuspendDoneSignal(proto);
}

void PowerdAdapterImpl::HandleLidClosed(dbus::Signal* signal) {
  for (auto& observer : lid_observers_)
    observer.OnLidClosedSignal();
}

void PowerdAdapterImpl::HandleLidOpened(dbus::Signal* signal) {
  for (auto& observer : lid_observers_)
    observer.OnLidOpenedSignal();
}

}  // namespace wilco
}  // namespace diagnostics
