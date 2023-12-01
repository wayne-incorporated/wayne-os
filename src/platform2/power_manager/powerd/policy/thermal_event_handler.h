// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_THERMAL_EVENT_HANDLER_H_
#define POWER_MANAGER_POWERD_POLICY_THERMAL_EVENT_HANDLER_H_

#include <memory>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <dbus/exported_object.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/thermal/device_thermal_state.h"
#include "power_manager/powerd/system/thermal/thermal_device_observer.h"

namespace dbus {
class MethodCall;
}

namespace power_manager {

class Clock;

namespace system {
class DBusWrapperInterface;
class ThermalDeviceInterface;
enum class DeviceThermalState;
}  // namespace system

namespace policy {

class ThermalEventHandler : public system::ThermalDeviceObserver {
 public:
  ThermalEventHandler(
      std::vector<system::ThermalDeviceInterface*> thermal_devices,
      system::DBusWrapperInterface* dbus_wrapper);
  ThermalEventHandler(const ThermalEventHandler&) = delete;
  ThermalEventHandler& operator=(const ThermalEventHandler&) = delete;

  ~ThermalEventHandler() override;

  Clock* clock_for_testing() { return clock_.get(); }

  bool Init();

  // ThermalDeviceObserver implementations.
  // Query all thermal devices and report thermal state of the entire device to
  // Chrome. Note that charger's cooling device thermal state is ignored when
  // power source is battery.
  void OnThermalChanged(system::ThermalDeviceInterface* device) override;

  void OnGetThermalStateMethodCall(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // Should be called when the power source changes.
  void HandlePowerSourceChange(PowerSource source);

 private:
  system::DBusWrapperInterface* dbus_wrapper_ = nullptr;          //  Not owned.
  std::vector<system::ThermalDeviceInterface*> thermal_devices_;  //  Not owned.

  // Clock for current timestamp.
  std::unique_ptr<Clock> clock_;

  // Last DeviceThermalState sent to Chrome.
  system::DeviceThermalState last_state_ = system::DeviceThermalState::kUnknown;

  PowerSource power_source_ = PowerSource::AC;

  base::WeakPtrFactory<ThermalEventHandler> weak_ptr_factory_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_THERMAL_EVENT_HANDLER_H_
