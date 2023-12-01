// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/thermal_event_handler.h"

#include <algorithm>
#include <memory>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>

#include "power_manager/common/clock.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/powerd/system/thermal/device_thermal_state.h"
#include "power_manager/powerd/system/thermal/thermal_device.h"
#include "power_manager/powerd/system/thermal/thermal_device_observer.h"
#include "power_manager/proto_bindings/thermal.pb.h"

namespace power_manager::policy {

namespace {

system::DeviceThermalState max(system::DeviceThermalState a,
                               system::DeviceThermalState b) {
  return static_cast<int>(a) >= static_cast<int>(b) ? a : b;
}

}  // namespace

ThermalEventHandler::ThermalEventHandler(
    std::vector<system::ThermalDeviceInterface*> thermal_devices,
    system::DBusWrapperInterface* dbus_wrapper)
    : dbus_wrapper_(dbus_wrapper),
      thermal_devices_(thermal_devices),
      clock_(std::make_unique<Clock>()),
      weak_ptr_factory_(this) {
  for (auto& device : thermal_devices) {
    DCHECK(device);
    device->AddObserver(this);
  }
}

ThermalEventHandler::~ThermalEventHandler() {
  for (auto& device : thermal_devices_) {
    device->RemoveObserver(this);
  }
}

bool ThermalEventHandler::Init() {
  // Send current state to Chrome on Init.
  OnThermalChanged(nullptr);
  dbus_wrapper_->ExportMethod(
      kGetThermalStateMethod,
      base::BindRepeating(&ThermalEventHandler::OnGetThermalStateMethodCall,
                          weak_ptr_factory_.GetWeakPtr()));
  return true;
}

void ThermalEventHandler::OnGetThermalStateMethodCall(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  ThermalEvent protobuf;
  protobuf.set_thermal_state(DeviceThermalStateToProto(last_state_));
  protobuf.set_timestamp(
      (clock_->GetCurrentTime() - base::TimeTicks()).InMicroseconds());
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter writer(response.get());
  writer.AppendProtoAsArrayOfBytes(protobuf);
  std::move(response_sender).Run(std::move(response));
}

void ThermalEventHandler::OnThermalChanged(
    system::ThermalDeviceInterface* device) {
  if (device && device->GetThermalState() == last_state_)
    return;

  // Query all devices and send max_state.
  system::DeviceThermalState new_state = system::DeviceThermalState::kUnknown;
  for (const auto& thermal_device : thermal_devices_) {
    auto state = thermal_device->GetThermalState();
    // Charger cooling device may report bogus thermal state when device is on
    // battery, ignore it in this case.
    if (power_source_ == PowerSource::BATTERY &&
        thermal_device->GetType() ==
            system::ThermalDeviceType::kChargerCooling) {
      state = system::DeviceThermalState::kUnknown;
    }
    new_state = max(new_state, state);
  }
  if (new_state == last_state_)
    return;

  ThermalEvent proto;
  proto.set_thermal_state(DeviceThermalStateToProto(new_state));
  proto.set_timestamp(
      (clock_->GetCurrentTime() - base::TimeTicks()).InMicroseconds());
  dbus_wrapper_->EmitSignalWithProtocolBuffer(kThermalEventSignal, proto);

  last_state_ = new_state;
}

void ThermalEventHandler::HandlePowerSourceChange(PowerSource source) {
  if (source == power_source_)
    return;

  power_source_ = source;

  // No need to recalculate thermal state if it is already at nominal.
  if (last_state_ == system::DeviceThermalState::kNominal ||
      last_state_ == system::DeviceThermalState::kUnknown)
    return;

  OnThermalChanged(nullptr);
}

}  // namespace power_manager::policy
