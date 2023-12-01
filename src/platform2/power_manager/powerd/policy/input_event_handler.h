// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef POWER_MANAGER_POWERD_POLICY_INPUT_EVENT_HANDLER_H_
#define POWER_MANAGER_POWERD_POLICY_INPUT_EVENT_HANDLER_H_

#include <memory>

#include <base/compiler_specific.h>
#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <base/timer/timer.h>
#include <base/time/time.h>
#include <dbus/exported_object.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/system/input_observer.h"

namespace dbus {
class MethodCall;
}

namespace power_manager {

class Clock;
class PrefsInterface;

namespace system {
class DBusWrapperInterface;
class DisplayWatcherInterface;
class InputWatcherInterface;
}  // namespace system

namespace policy {

// InputEventHandler responds to input events (e.g. lid open/close, power
// button, etc.).
class InputEventHandler : public system::InputObserver {
 public:
  // Interface for delegates responsible for performing actions on behalf of
  // InputEventHandler.
  class Delegate {
   public:
    virtual ~Delegate() = default;

    // Handles the lid being closed.
    virtual void HandleLidClosed() = 0;

    // Handles the lid being opened.
    virtual void HandleLidOpened() = 0;

    // Handles the power button being pressed or released.
    virtual void HandlePowerButtonEvent(ButtonState state) = 0;

    // Handles hovering/proximity changes.
    virtual void HandleHoverStateChange(bool hovering) = 0;

    // Handles the device entering or leaving tablet mode.
    // TabletMode::UNSUPPORTED will never be passed.
    virtual void HandleTabletModeChange(TabletMode mode) = 0;

    // Shuts the system down in response to the power button being pressed while
    // no display is connected.
    virtual void ShutDownForPowerButtonWithNoDisplay() = 0;

    // Handles Chrome failing to acknowledge a power button press quickly
    // enough.
    virtual void HandleMissingPowerButtonAcknowledgment() = 0;

    // Sends a metric reporting how long Chrome took to acknowledge a power
    // button press.
    virtual void ReportPowerButtonAcknowledgmentDelay(
        base::TimeDelta delay) = 0;
  };

  // Amount of time to wait for Chrome to acknowledge power button presses.
  static constexpr base::TimeDelta kPowerButtonAcknowledgmentTimeout =
      base::Seconds(2);

  InputEventHandler();
  InputEventHandler(const InputEventHandler&) = delete;
  InputEventHandler& operator=(const InputEventHandler&) = delete;

  ~InputEventHandler() override;

  Clock* clock_for_testing() { return clock_.get(); }

  // Ownership of passed-in pointers remains with the caller.
  void Init(system::InputWatcherInterface* input_watcher,
            Delegate* delegate,
            system::DisplayWatcherInterface* display_watcher,
            system::DBusWrapperInterface* dbus_wrapper,
            PrefsInterface* prefs);

  // Calls HandlePowerButtonAcknowledgmentTimeout(). Returns false if
  // |power_button_acknowledgment_timer_| isn't running.
  bool TriggerPowerButtonAcknowledgmentTimeoutForTesting();

  // system::InputObserver implementation:
  void OnLidEvent(LidState state) override;
  void OnTabletModeEvent(TabletMode mode) override;
  void OnPowerButtonEvent(ButtonState state) override;
  void OnHoverStateChange(bool hovering) override;

 private:
  // Discards all power button actions until |timeout| has elapsed
  // or a power button release was detected. Set |timeout| to 0 to cancel it.
  void IgnoreNextPowerButtonPress(const base::TimeDelta& timeout);

  // Tells |delegate_| when Chrome hasn't acknowledged a power button press
  // quickly enough.
  void OnPowerButtonAcknowledgmentTimeout();

  // Handlers for D-Bus method calls.
  void OnHandlePowerButtonAcknowledgmentMethodCall(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);
  void OnIgnoreNextPowerButtonPressMethodCall(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);
  void OnGetSwitchStatesMethodCall(
      dbus::MethodCall* method_call,
      dbus::ExportedObject::ResponseSender response_sender);

  // None of these objects are owned by this class.
  system::InputWatcherInterface* input_watcher_ = nullptr;
  Delegate* delegate_ = nullptr;
  system::DisplayWatcherInterface* display_watcher_ = nullptr;
  system::DBusWrapperInterface* dbus_wrapper_ = nullptr;

  std::unique_ptr<Clock> clock_;

  // True if the device doesn't have an internal display.
  bool only_has_external_display_ = false;

  // True if kFactoryModePref is set to true.
  bool factory_mode_ = false;

  LidState lid_state_ = LidState::NOT_PRESENT;
  TabletMode tablet_mode_ = TabletMode::UNSUPPORTED;

  // Timestamp from the most recent power-button-down event that Chrome is
  // expected to acknowledge. Unset when the power button isn't pressed or if
  // Chrome has already acknowledged the event.
  base::TimeTicks expected_power_button_acknowledgment_timestamp_;

  // Calls OnPowerButtonAcknowledgmentTimeout().
  base::OneShotTimer power_button_acknowledgment_timer_;

  // Timestamp until when we are ignoring actions on the power button.
  base::TimeTicks ignore_power_button_deadline_;
  // The last key down event on the power button was ignored.
  bool power_button_down_ignored_ = false;

  base::WeakPtrFactory<InputEventHandler> weak_ptr_factory_;
};

}  // namespace policy
}  // namespace power_manager

#endif  // POWER_MANAGER_POWERD_POLICY_INPUT_EVENT_HANDLER_H_
