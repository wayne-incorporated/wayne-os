// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/input_event_handler.h"

#include <utility>

#include <base/check_op.h>
#include <base/logging.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/message.h>

#include "power_manager/common/clock.h"
#include "power_manager/common/power_constants.h"
#include "power_manager/common/prefs.h"
#include "power_manager/common/tracing.h"
#include "power_manager/powerd/system/dbus_wrapper.h"
#include "power_manager/powerd/system/display/display_watcher.h"
#include "power_manager/powerd/system/input_watcher_interface.h"
#include "power_manager/proto_bindings/input_event.pb.h"
#include "power_manager/proto_bindings/switch_states.pb.h"

namespace power_manager::policy {

InputEventHandler::InputEventHandler()
    : clock_(std::make_unique<Clock>()), weak_ptr_factory_(this) {}

InputEventHandler::~InputEventHandler() {
  if (input_watcher_)
    input_watcher_->RemoveObserver(this);
}

void InputEventHandler::Init(system::InputWatcherInterface* input_watcher,
                             Delegate* delegate,
                             system::DisplayWatcherInterface* display_watcher,
                             system::DBusWrapperInterface* dbus_wrapper,
                             PrefsInterface* prefs) {
  input_watcher_ = input_watcher;
  input_watcher_->AddObserver(this);
  delegate_ = delegate;
  display_watcher_ = display_watcher;

  dbus_wrapper_ = dbus_wrapper;
  dbus_wrapper_->ExportMethod(
      kHandlePowerButtonAcknowledgmentMethod,
      base::BindRepeating(
          &InputEventHandler::OnHandlePowerButtonAcknowledgmentMethodCall,
          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper_->ExportMethod(
      kIgnoreNextPowerButtonPressMethod,
      base::BindRepeating(
          &InputEventHandler::OnIgnoreNextPowerButtonPressMethodCall,
          weak_ptr_factory_.GetWeakPtr()));
  dbus_wrapper_->ExportMethod(
      kGetSwitchStatesMethod,
      base::BindRepeating(&InputEventHandler::OnGetSwitchStatesMethodCall,
                          weak_ptr_factory_.GetWeakPtr()));

  prefs->GetBool(kExternalDisplayOnlyPref, &only_has_external_display_);
  prefs->GetBool(kFactoryModePref, &factory_mode_);

  bool use_lid = false;
  if (prefs->GetBool(kUseLidPref, &use_lid) && use_lid)
    lid_state_ = input_watcher_->QueryLidState();

  tablet_mode_ = input_watcher_->GetTabletMode();
}

bool InputEventHandler::TriggerPowerButtonAcknowledgmentTimeoutForTesting() {
  if (!power_button_acknowledgment_timer_.IsRunning())
    return false;

  power_button_acknowledgment_timer_.Stop();
  OnPowerButtonAcknowledgmentTimeout();
  return true;
}

void InputEventHandler::OnLidEvent(LidState state) {
  lid_state_ = state;
  InputEvent proto;
  switch (lid_state_) {
    case LidState::CLOSED:
      delegate_->HandleLidClosed();
      proto.set_type(InputEvent_Type_LID_CLOSED);
      break;
    case LidState::OPEN:
      delegate_->HandleLidOpened();
      proto.set_type(InputEvent_Type_LID_OPEN);
      break;
    case LidState::NOT_PRESENT:
      return;
  }
  proto.set_timestamp(
      (clock_->GetCurrentTime() - base::TimeTicks()).InMicroseconds());
  dbus_wrapper_->EmitSignalWithProtocolBuffer(kInputEventSignal, proto);
}

void InputEventHandler::OnTabletModeEvent(TabletMode mode) {
  DCHECK_NE(mode, TabletMode::UNSUPPORTED);
  tablet_mode_ = mode;

  delegate_->HandleTabletModeChange(mode);

  InputEvent proto;
  proto.set_type(tablet_mode_ == TabletMode::ON
                     ? InputEvent_Type_TABLET_MODE_ON
                     : InputEvent_Type_TABLET_MODE_OFF);
  proto.set_timestamp(
      (clock_->GetCurrentTime() - base::TimeTicks()).InMicroseconds());
  dbus_wrapper_->EmitSignalWithProtocolBuffer(kInputEventSignal, proto);
}

void InputEventHandler::OnPowerButtonEvent(ButtonState state) {
  if (factory_mode_) {
    LOG(INFO) << "Ignoring power button " << ButtonStateToString(state)
              << " for factory mode";
    return;
  }

  if (clock_->GetCurrentTime() < ignore_power_button_deadline_) {
    bool ignore = state == ButtonState::DOWN || power_button_down_ignored_;
    if (state == ButtonState::UP)  // Consumed, we no longer need the deadline.
      IgnoreNextPowerButtonPress(base::TimeDelta());
    else if (state == ButtonState::DOWN)
      power_button_down_ignored_ = true;
    if (ignore) {
      // Ignore down event or up event if it matches a down event.
      LOG(INFO) << "Ignored power button " << ButtonStateToString(state);
      // Do not forward this event.
      return;
    }
  }

  if (state == ButtonState::DOWN && only_has_external_display_ &&
      display_watcher_->GetDisplays().empty()) {
    delegate_->ShutDownForPowerButtonWithNoDisplay();
    return;
  }

  if (state != ButtonState::REPEAT) {
    const base::TimeTicks now = clock_->GetCurrentTime();

    InputEvent proto;
    proto.set_type(state == ButtonState::DOWN
                       ? InputEvent_Type_POWER_BUTTON_DOWN
                       : InputEvent_Type_POWER_BUTTON_UP);
    proto.set_timestamp((now - base::TimeTicks()).InMicroseconds());
    dbus_wrapper_->EmitSignalWithProtocolBuffer(kInputEventSignal, proto);

    if (state == ButtonState::DOWN) {
      expected_power_button_acknowledgment_timestamp_ = now;
      power_button_acknowledgment_timer_.Start(
          FROM_HERE, kPowerButtonAcknowledgmentTimeout, this,
          &InputEventHandler::OnPowerButtonAcknowledgmentTimeout);
    } else {
      expected_power_button_acknowledgment_timestamp_ = base::TimeTicks();
      power_button_acknowledgment_timer_.Stop();
    }
  }

  delegate_->HandlePowerButtonEvent(state);
}

void InputEventHandler::OnHoverStateChange(bool hovering) {
  delegate_->HandleHoverStateChange(hovering);
}

void InputEventHandler::IgnoreNextPowerButtonPress(
    const base::TimeDelta& timeout) {
  if (timeout.is_zero()) {
    VLOG(1) << "Cancel power button press discarding";
    ignore_power_button_deadline_ = base::TimeTicks();
    power_button_down_ignored_ = false;
  } else {
    VLOG(1) << "Ignoring power button for " << timeout.InMilliseconds()
            << " ms";
    ignore_power_button_deadline_ = clock_->GetCurrentTime() + timeout;
  }
}

void InputEventHandler::OnPowerButtonAcknowledgmentTimeout() {
  TRACE_EVENT("power", "InputEventHandler::OnPowerButtonAcknowledgmentTimeout");
  delegate_->ReportPowerButtonAcknowledgmentDelay(
      kPowerButtonAcknowledgmentTimeout);
  delegate_->HandleMissingPowerButtonAcknowledgment();
  expected_power_button_acknowledgment_timestamp_ = base::TimeTicks();
}

void InputEventHandler::OnHandlePowerButtonAcknowledgmentMethodCall(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  int64_t timestamp_internal = 0;
  dbus::MessageReader reader(method_call);
  if (!reader.PopInt64(&timestamp_internal)) {
    LOG(ERROR) << "Unable to parse " << kHandlePowerButtonAcknowledgmentMethod
               << " request";
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(method_call,
                                                 DBUS_ERROR_INVALID_ARGS,
                                                 "Expected int64_t timestamp"));
    return;
  }

  const auto timestamp =
      base::TimeTicks() + base::Microseconds(timestamp_internal);
  VLOG(1) << "Received acknowledgment of power button press at "
          << timestamp_internal << "; expected "
          << (expected_power_button_acknowledgment_timestamp_ -
              base::TimeTicks())
                 .InMicroseconds();
  if (timestamp == expected_power_button_acknowledgment_timestamp_) {
    delegate_->ReportPowerButtonAcknowledgmentDelay(
        clock_->GetCurrentTime() -
        expected_power_button_acknowledgment_timestamp_);
    expected_power_button_acknowledgment_timestamp_ = base::TimeTicks();
    power_button_acknowledgment_timer_.Stop();
  }
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void InputEventHandler::OnIgnoreNextPowerButtonPressMethodCall(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  int64_t timeout_internal = 0;
  dbus::MessageReader reader(method_call);
  if (!reader.PopInt64(&timeout_internal)) {
    LOG(ERROR) << "Unable to parse " << kIgnoreNextPowerButtonPressMethod
               << " request";
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(method_call,
                                                 DBUS_ERROR_INVALID_ARGS,
                                                 "Expected int64_t timestamp"));
    return;
  }

  IgnoreNextPowerButtonPress(base::Microseconds(timeout_internal));
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void InputEventHandler::OnGetSwitchStatesMethodCall(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  SwitchStates protobuf;
  switch (input_watcher_->GetTabletMode()) {
    case TabletMode::ON:
      protobuf.set_tablet_mode(SwitchStates_TabletMode_ON);
      break;
    case TabletMode::OFF:
      protobuf.set_tablet_mode(SwitchStates_TabletMode_OFF);
      break;
    case TabletMode::UNSUPPORTED:
      protobuf.set_tablet_mode(SwitchStates_TabletMode_UNSUPPORTED);
      break;
  }
  switch (input_watcher_->QueryLidState()) {
    case LidState::OPEN:
      protobuf.set_lid_state(SwitchStates_LidState_OPEN);
      break;
    case LidState::CLOSED:
      protobuf.set_lid_state(SwitchStates_LidState_CLOSED);
      break;
    case LidState::NOT_PRESENT:
      protobuf.set_lid_state(SwitchStates_LidState_NOT_PRESENT);
      break;
  }

  std::unique_ptr<dbus::Response> response(
      dbus::Response::FromMethodCall(method_call));
  dbus::MessageWriter writer(response.get());
  writer.AppendProtoAsArrayOfBytes(protobuf);
  std::move(response_sender).Run(std::move(response));
}

}  // namespace power_manager::policy
