// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/functional/bind.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/message.h>
#include <dbus/object_proxy.h>
#include <string>

#include "federated/power_supply_training_condition.h"
#include "power_manager/proto_bindings/power_supply_properties.pb.h"

namespace federated {
namespace {

// TODO(alanlxl): use 90% for now.
constexpr double kMinimumAdequateBatteryLevel = 90.0;

void OnSignalConnected(const std::string& interface_name,
                       const std::string& signal_name,
                       bool success) {
  if (!success) {
    LOG(ERROR) << "Failed to connect to signal " << interface_name << ":"
               << signal_name << ".";
  }
}
}  // namespace

PowerSupplyTrainingCondition::PowerSupplyTrainingCondition(dbus::Bus* bus)
    : powerd_dbus_proxy_(bus->GetObjectProxy(
          power_manager::kPowerManagerServiceName,
          dbus::ObjectPath(power_manager::kPowerManagerServicePath))),
      enough_battery_(false),
      weak_ptr_factory_(this) {
  DCHECK_NE(powerd_dbus_proxy_, nullptr);
  // Updates the battery status when receiving the kPowerSupplyPollSignal.
  powerd_dbus_proxy_->ConnectToSignal(
      power_manager::kPowerManagerInterface,
      power_manager::kPowerSupplyPollSignal,
      base::BindRepeating(&PowerSupplyTrainingCondition::OnPowerSupplyReceived,
                          weak_ptr_factory_.GetMutableWeakPtr()),
      base::BindOnce(&OnSignalConnected));

  DVLOG(1) << "Construct PowerSupplyTrainingCondition";
}

bool PowerSupplyTrainingCondition::IsTrainingConditionSatisfied() const {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  DVLOG(1) << "PowerSupplyTrainingCondition::IsTrainingConditionSatisfied: "
           << enough_battery_;
  return enough_battery_;
}

void PowerSupplyTrainingCondition::OnPowerSupplyReceived(
    dbus::Signal* const signal) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  if (signal == nullptr) {
    DVLOG(1) << "Received a null signal in OnPowerSupplyReceived.";
    enough_battery_ = false;
    return;
  }

  dbus::MessageReader reader(signal);
  power_manager::PowerSupplyProperties power_supply_proto;
  if (!reader.PopArrayOfBytesAsProto(&power_supply_proto)) {
    DVLOG(1) << "Failed to read PowerSupplyProperties proto from dbus message.";
    enough_battery_ = false;
    return;
  }

  // When battery is enough, or the device is plugged-in.
  enough_battery_ =
      (power_supply_proto.has_battery_percent() &&
       power_supply_proto.battery_percent() > kMinimumAdequateBatteryLevel) ||
      (power_supply_proto.has_battery_state() &&
       power_supply_proto.battery_state() !=
           power_manager::PowerSupplyProperties::DISCHARGING);
}

}  // namespace federated
