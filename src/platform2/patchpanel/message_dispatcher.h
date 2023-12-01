// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_MESSAGE_DISPATCHER_H_
#define PATCHPANEL_MESSAGE_DISPATCHER_H_

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <sys/socket.h>

#include <base/files/scoped_file.h>
#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>
#include <google/protobuf/message_lite.h>

#include "patchpanel/file_descriptor_watcher_posix.h"

namespace patchpanel {

class BRILLO_EXPORT MessageDispatcherInternal {
 public:
  explicit MessageDispatcherInternal(base::ScopedFD fd);
  MessageDispatcherInternal(const MessageDispatcherInternal&) = delete;
  MessageDispatcherInternal& operator=(const MessageDispatcherInternal&) =
      delete;

  ~MessageDispatcherInternal() = default;

  void RegisterFailureHandler(base::RepeatingCallback<void()> handler);
  void RegisterMessageHandler(base::RepeatingCallback<void()> handler);

  bool GetMessage(google::protobuf::MessageLite* proto);
  bool SendMessage(const google::protobuf::MessageLite& proto);

 private:
  base::ScopedFD fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
  base::RepeatingCallback<void()> failure_handler_;
};

// Helper message processor
template <typename ProtoMessage>
class BRILLO_EXPORT MessageDispatcher {
 public:
  explicit MessageDispatcher(base::ScopedFD fd)
      : msg_dispatcher_internal_(new MessageDispatcherInternal(std::move(fd))) {
  }
  MessageDispatcher(const MessageDispatcher&) = delete;
  MessageDispatcher& operator=(const MessageDispatcher&) = delete;

  virtual ~MessageDispatcher() = default;

  virtual void RegisterFailureHandler(base::RepeatingCallback<void()> handler) {
    msg_dispatcher_internal_->RegisterFailureHandler(std::move(handler));
  }

  virtual void RegisterMessageHandler(
      base::RepeatingCallback<void(const ProtoMessage&)> handler) {
    message_handler_ = std::move(handler);
    msg_dispatcher_internal_->RegisterMessageHandler(
        base::BindRepeating(&MessageDispatcher::OnFileCanReadWithoutBlocking,
                            weak_factory_.GetWeakPtr()));
  }

  virtual bool SendMessage(const ProtoMessage& proto) const {
    return msg_dispatcher_internal_->SendMessage(proto);
  }

 private:
  void OnFileCanReadWithoutBlocking() {
    if (!msg_dispatcher_internal_->GetMessage(&msg_)) {
      return;
    }
    if (!message_handler_.is_null()) {
      message_handler_.Run(msg_);
    }
  }

  std::unique_ptr<MessageDispatcherInternal> msg_dispatcher_internal_;
  base::RepeatingCallback<void(const ProtoMessage&)> message_handler_;

  ProtoMessage msg_;

  base::WeakPtrFactory<MessageDispatcher> weak_factory_{this};
};

}  // namespace patchpanel

#endif  // PATCHPANEL_MESSAGE_DISPATCHER_H_
