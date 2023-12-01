// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "feedback/feedback_service.h"

#include <memory>
#include <utility>

#include "base/logging.h"
#include "chromeos/dbus/service_constants.h"
#include "components/feedback/feedback_uploader.h"
#include "components/feedback/proto/extension.pb.h"
#include "dbus/bus.h"
#include "dbus/exported_object.h"
#include "dbus/message.h"
#include "dbus/object_proxy.h"

namespace feedback {

FeedbackService::FeedbackService(feedback::FeedbackUploader* uploader)
    : uploader_(uploader) {}

FeedbackService::~FeedbackService() {}

void FeedbackService::SendFeedback(
    const userfeedback::ExtensionSubmit& report,
    base::OnceCallback<void(bool, const std::string&)> callback) {
  std::string data;
  report.SerializeToString(&data);
  uploader_->QueueReport(data);

  // Currently, we don't implement status reporting; if QueueReport
  // returns then the report is at least queued.
  std::move(callback).Run(true, std::string());
}

void FeedbackService::QueueExistingReport(const std::string& data) {
  uploader_->QueueReport(data);
}

DBusFeedbackServiceImpl::DBusFeedbackServiceImpl(
    feedback::FeedbackUploader* uploader)
    : FeedbackService(uploader) {}

DBusFeedbackServiceImpl::~DBusFeedbackServiceImpl() {}

bool DBusFeedbackServiceImpl::Start(dbus::Bus* bus) {
  if (!bus || !bus->Connect()) {
    LOG(ERROR) << "Failed to connect to DBus";
    return false;
  }

  dbus::ObjectPath path(feedback::kFeedbackServicePath);
  dbus::ExportedObject* object = bus->GetExportedObject(path);
  if (!object) {
    LOG(ERROR) << "Failed to get exported object at " << path.value();
    return false;
  }

  if (!object->ExportMethodAndBlock(
          feedback::kFeedbackServiceName, feedback::kSendFeedback,
          base::BindRepeating(&DBusFeedbackServiceImpl::DBusSendFeedback,
                              this))) {
    bus->UnregisterExportedObject(path);
    LOG(ERROR) << "Failed to export method " << feedback::kSendFeedback;
    return false;
  }
  if (!bus->RequestOwnershipAndBlock(feedback::kFeedbackServiceName,
                                     dbus::Bus::REQUIRE_PRIMARY)) {
    bus->UnregisterExportedObject(path);
    LOG(ERROR) << "Failed to get ownership of "
               << feedback::kFeedbackServiceName;
    return false;
  }
  return true;
}

void DBusFeedbackServiceImpl::DBusSendFeedback(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender sender) {
  dbus::MessageReader reader(method_call);
  userfeedback::ExtensionSubmit in;
  if (!reader.PopArrayOfBytesAsProto(&in)) {
    LOG(ERROR) << "Got feedback request with bad param";
    DBusFeedbackSent(
        method_call, std::move(sender), false,
        "Can't deserialize proto of type userfeedback::ExtensionSubmit");
  } else {
    LOG(INFO) << "Sending feedback";
    SendFeedback(in, base::BindOnce(&DBusFeedbackServiceImpl::DBusFeedbackSent,
                                    this, method_call, std::move(sender)));
  }
}

void DBusFeedbackServiceImpl::DBusFeedbackSent(
    dbus::MethodCall* method_call,
    dbus::ExportedObject::ResponseSender sender,
    bool status,
    const std::string& reason) {
  std::unique_ptr<dbus::Response> response =
      dbus::Response::FromMethodCall(method_call);
  dbus::MessageWriter writer(response.get());
  writer.AppendBool(status);
  writer.AppendString(reason);
  std::move(sender).Run(std::move(response));
}

}  // namespace feedback
