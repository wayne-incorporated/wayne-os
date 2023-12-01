// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <dbus/exported_object.h>
#include <dbus/message.h>

#include "power_manager/powerd/policy/backlight_controller.h"

#include "power_manager/powerd/system/dbus_wrapper.h"

namespace power_manager::policy {

namespace {

void OnIncreaseBrightness(
    const BacklightController::IncreaseBrightnessCallback& callback,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  callback.Run();
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void OnDecreaseBrightness(
    const BacklightController::DecreaseBrightnessCallback& callback,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  bool allow_off = true;
  if (!dbus::MessageReader(method_call).PopBool(&allow_off))
    allow_off = true;

  callback.Run(allow_off);
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void OnSetBrightness(const std::string& method_name,
                     const BacklightController::SetBrightnessCallback& callback,
                     dbus::MethodCall* method_call,
                     dbus::ExportedObject::ResponseSender response_sender) {
  dbus::MessageReader reader(method_call);
  SetBacklightBrightnessRequest request;
  if (!reader.PopArrayOfBytesAsProto(&request)) {
    LOG(ERROR) << "Invalid " << method_name << " args";
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(
            method_call, DBUS_ERROR_INVALID_ARGS,
            "Expected SetBacklightBrightnessRequest protobuf"));
    return;
  }

  using Transition = policy::BacklightController::Transition;
  Transition transition = Transition::FAST;
  switch (request.transition()) {
    case SetBacklightBrightnessRequest_Transition_INSTANT:
      transition = Transition::INSTANT;
      break;
    case SetBacklightBrightnessRequest_Transition_FAST:
      transition = Transition::FAST;
      break;
    case SetBacklightBrightnessRequest_Transition_SLOW:
      transition = Transition::SLOW;
      break;
  }

  callback.Run(request.percent(), transition, request.cause());
  std::move(response_sender).Run(dbus::Response::FromMethodCall(method_call));
}

void OnGetBrightness(const std::string& method_name,
                     const BacklightController::GetBrightnessCallback& callback,
                     dbus::MethodCall* method_call,
                     dbus::ExportedObject::ResponseSender response_sender) {
  double percent = 0.0;
  bool success = false;
  callback.Run(&percent, &success);
  if (!success) {
    std::move(response_sender)
        .Run(dbus::ErrorResponse::FromMethodCall(method_call, DBUS_ERROR_FAILED,
                                                 "Couldn't fetch brightness"));
    return;
  }

  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter(response.get()).AppendDouble(percent);
  std::move(response_sender).Run(std::move(response));
}

void OnToggleKeyboardBacklight(
    const std::string& method_name,
    const BacklightController::ToggleKeyboardBacklightCallback& callback,
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender response_sender) {
  callback.Run();
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  std::move(response_sender).Run(std::move(response));
}

}  // namespace

// static
void BacklightController::RegisterIncreaseBrightnessHandler(
    system::DBusWrapperInterface* dbus_wrapper,
    const std::string& method_name,
    const IncreaseBrightnessCallback& callback) {
  DCHECK(dbus_wrapper);
  dbus_wrapper->ExportMethod(
      method_name, base::BindRepeating(&OnIncreaseBrightness, callback));
}

// static
void BacklightController::RegisterDecreaseBrightnessHandler(
    system::DBusWrapperInterface* dbus_wrapper,
    const std::string& method_name,
    const DecreaseBrightnessCallback& callback) {
  DCHECK(dbus_wrapper);
  dbus_wrapper->ExportMethod(
      method_name, base::BindRepeating(&OnDecreaseBrightness, callback));
}

// static
void BacklightController::RegisterSetBrightnessHandler(
    system::DBusWrapperInterface* dbus_wrapper,
    const std::string& method_name,
    const SetBrightnessCallback& callback) {
  DCHECK(dbus_wrapper);
  dbus_wrapper->ExportMethod(
      method_name,
      base::BindRepeating(&OnSetBrightness, method_name, callback));
}

// static
void BacklightController::RegisterGetBrightnessHandler(
    system::DBusWrapperInterface* dbus_wrapper,
    const std::string& method_name,
    const GetBrightnessCallback& callback) {
  DCHECK(dbus_wrapper);
  dbus_wrapper->ExportMethod(
      method_name,
      base::BindRepeating(&OnGetBrightness, method_name, callback));
}

// static
void BacklightController::RegisterToggleKeyboardBacklightHandler(
    system::DBusWrapperInterface* dbus_wrapper,
    const std::string& method_name,
    const ToggleKeyboardBacklightCallback& callback) {
  DCHECK(dbus_wrapper);
  dbus_wrapper->ExportMethod(
      method_name,
      base::BindRepeating(&OnToggleKeyboardBacklight, method_name, callback));
}

// static
void BacklightController::EmitBrightnessChangedSignal(
    system::DBusWrapperInterface* dbus_wrapper,
    const std::string& signal_name,
    double brightness_percent,
    BacklightBrightnessChange_Cause cause) {
  DCHECK(dbus_wrapper);
  dbus::Signal signal(kPowerManagerInterface, signal_name);
  BacklightBrightnessChange proto;
  proto.set_percent(brightness_percent);
  proto.set_cause(cause);
  dbus::MessageWriter(&signal).AppendProtoAsArrayOfBytes(proto);
  dbus_wrapper->EmitSignal(&signal);
}

}  // namespace power_manager::policy
