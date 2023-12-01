// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "feedback/feedback_service_interface.h"

#include <memory>
#include <utility>

#include "base/functional/bind.h"
#include "chromeos/dbus/service_constants.h"
#include "components/feedback/feedback_common.h"
#include "components/feedback/proto/extension.pb.h"
#include "dbus/object_proxy.h"

DBusFeedbackServiceInterface::DBusFeedbackServiceInterface() {
  dbus::Bus::Options options;
  options.bus_type = dbus::Bus::SYSTEM;
  bus_ = new dbus::Bus(options);
}

bool DBusFeedbackServiceInterface::SendFeedback(
    const FeedbackCommon& feedback, FeedbackResultCallback callback) {
  // A product ID of 0 generally means that the caller just forgot to
  // set it at all, and an empty description is apparently ignored
  // by the feedback servers.
  if (feedback.description().empty() || feedback.product_id() == 0) {
    return false;
  }

  userfeedback::ExtensionSubmit submit;
  feedback.PrepareReport(&submit);

  dbus::MethodCall call(feedback::kFeedbackServiceName,
                        feedback::kSendFeedback);

  dbus::MessageWriter writer(&call);
  writer.AppendProtoAsArrayOfBytes(submit);

  dbus::ObjectProxy* object =
      bus_->GetObjectProxy(feedback::kFeedbackServiceName,
                           dbus::ObjectPath(feedback::kFeedbackServicePath));

  std::unique_ptr<dbus::Response> response =
      object->CallMethodAndBlock(&call, dbus::ObjectProxy::TIMEOUT_USE_DEFAULT);
  if (response.get() == nullptr) {
    std::move(callback).Run(false);
    return true;
  }

  bool status = false;
  const auto& message_type = response->GetMessageType();
  if (message_type == dbus::ErrorResponse::MESSAGE_METHOD_RETURN) {
    dbus::MessageReader reader(response.get());
    reader.PopBool(&status);
  }

  std::move(callback).Run(status);
  return true;
}
