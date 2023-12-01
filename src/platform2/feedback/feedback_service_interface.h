// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FEEDBACK_FEEDBACK_SERVICE_INTERFACE_H_
#define FEEDBACK_FEEDBACK_SERVICE_INTERFACE_H_

#include "base/functional/callback.h"
#include "base/memory/ref_counted.h"
#include "dbus/bus.h"
#include "dbus/message.h"

namespace base {
class Thread;
}

class FeedbackCommon;

typedef base::OnceCallback<void(bool status)> FeedbackResultCallback;

class FeedbackServiceInterface
    : public base::RefCountedThreadSafe<FeedbackServiceInterface> {
 public:
  // Attempt to send the provided feedback report. If the report is invalid
  // (empty description or product ID of 0) then false will be returned.
  // Otherwise, this will return true and the provided callback
  // will be called with true if the report is successfully sent, or queued
  // for later upload, and false if there was an error talking to the
  // feedback service daemon.
  virtual bool SendFeedback(const FeedbackCommon& feedback,
                            FeedbackResultCallback callback) = 0;

 protected:
  friend class base::RefCountedThreadSafe<FeedbackServiceInterface>;
  virtual ~FeedbackServiceInterface() {}
};

// Sending feedback example
// void some_callback(bool success) {}
//
// base::Thread thread("Feedback DBus thread");
// base::Thread::Options opts(base::MessageLoop::TYPE_IO, 0);
// thread.StartWithOptions(opts);
// DBusFeedbackServiceInterface service(&thread);
// FeedbackCommon feedback;
// feedback.set_user_email(...)
// feedback.set_description(...)
// ...
// feedback.AddFile(attachment_name, attachment_data);
// ...
// feedback.AddLog(log_name, log_data);
// ...
// feedback.CompressLogs();
// service.SendFeedback(feedback, base::BindOnce(&some_callback))
class DBusFeedbackServiceInterface : public FeedbackServiceInterface {
 public:
  DBusFeedbackServiceInterface();
  DBusFeedbackServiceInterface(const DBusFeedbackServiceInterface&) = delete;
  DBusFeedbackServiceInterface& operator=(const DBusFeedbackServiceInterface&) =
      delete;

  bool SendFeedback(const FeedbackCommon& feedback,
                    FeedbackResultCallback callback) override;

 private:
  scoped_refptr<dbus::Bus> bus_;
};

#endif  // FEEDBACK_FEEDBACK_SERVICE_INTERFACE_H_
