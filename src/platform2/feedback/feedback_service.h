// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEEDBACK_FEEDBACK_SERVICE_H_
#define FEEDBACK_FEEDBACK_SERVICE_H_

#include "dbus/exported_object.h"

#include <string>

namespace userfeedback {
class ExtensionSubmit;
}

namespace feedback {

class FeedbackUploader;

class FeedbackService : public base::RefCounted<FeedbackService> {
 public:
  explicit FeedbackService(feedback::FeedbackUploader* uploader);
  FeedbackService(const FeedbackService&) = delete;
  FeedbackService& operator=(const FeedbackService&) = delete;

  virtual ~FeedbackService();

  // Send the given report to the server |uploader_| is configured for.
  // The callback will be called with
  void SendFeedback(
      const userfeedback::ExtensionSubmit& feedback,
      base::OnceCallback<void(bool, const std::string&)> callback);

  void QueueExistingReport(const std::string& data);

 private:
  feedback::FeedbackUploader* uploader_;
};

class DBusFeedbackServiceImpl : public FeedbackService {
 public:
  explicit DBusFeedbackServiceImpl(feedback::FeedbackUploader* uploader);
  DBusFeedbackServiceImpl(const DBusFeedbackServiceImpl&) = delete;
  DBusFeedbackServiceImpl& operator=(const DBusFeedbackServiceImpl&) = delete;

  virtual ~DBusFeedbackServiceImpl();

  bool Start(dbus::Bus* bus);

 private:
  void DBusSendFeedback(dbus::MethodCall* method_call,
                        dbus::ExportedObject::ResponseSender sender);

  void DBusFeedbackSent(dbus::MethodCall* method_call,
                        dbus::ExportedObject::ResponseSender sender,
                        bool status,
                        const std::string& message);
};

}  // namespace feedback

#endif  // FEEDBACK_FEEDBACK_SERVICE_H_
