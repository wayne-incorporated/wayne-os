// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_BATTERY_SAVER_CONTROLLER_H_
#define POWER_MANAGER_POWERD_POLICY_BATTERY_SAVER_CONTROLLER_H_

#include <memory>
#include <unordered_set>
#include <utility>

#include <base/observer_list.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>
#include <power_manager/proto_bindings/battery_saver.pb.h>

#include "power_manager/powerd/system/dbus_wrapper.h"

namespace power_manager::policy {

// Controls the state of Battery Saver Mode (BSM) on the system.
//
// BatterySaverController is not directly responsible for implementing
// any battery saving measures, but rather manages the current state of
// BSM and signals other components in the system about changes to the
// BSM state.
class BatterySaverController : public system::DBusWrapper::Observer {
 public:
  class Observer : public base::CheckedObserver {
   public:
    virtual void OnBatterySaverStateChanged(
        const BatterySaverModeState& state) = 0;
  };

  BatterySaverController();

  // Disallow copy and move.
  BatterySaverController(const BatterySaverController&) = delete;
  BatterySaverController& operator=(const BatterySaverController&) = delete;

  ~BatterySaverController() override;

  // Initialize this class instance.
  //
  // `dbus_wrapper` must outlive this class instance.
  void Init(system::DBusWrapperInterface& dbus_wrapper);

  // `system::DBusWrapper::Observer` implementation
  void OnServicePublished() override;

  void AddObserver(Observer* observer);
  void RemoveObserver(Observer* observer);

 private:
  // Handle DBus requests to get/set the state of Battery Saver Mode.
  void OnGetStateCall(dbus::MethodCall* method_call,
                      dbus::ExportedObject::ResponseSender response_sender);
  void OnSetStateCall(dbus::MethodCall* method_call,
                      dbus::ExportedObject::ResponseSender response_sender);

  // Get or set the current state of BSM.
  BatterySaverModeState GetState() const;
  void SetState(const SetBatterySaverModeStateRequest& request);

  // Send a D-Bus signal indicating a change of BSM state.
  void SendStateChangeSignal(BatterySaverModeState::Cause cause);

  // The current state of BSM.
  bool enabled_ = false;

  system::DBusWrapperInterface* dbus_wrapper_ = nullptr;  // Owned elsewhere

  base::ObserverList<Observer> observer_list_;

  base::WeakPtrFactory<BatterySaverController> weak_ptr_factory_{
      this};  // must be last
};

}  // namespace power_manager::policy

#endif  // POWER_MANAGER_POWERD_POLICY_BATTERY_SAVER_CONTROLLER_H_
