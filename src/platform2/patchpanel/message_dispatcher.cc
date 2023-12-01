// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/message_dispatcher.h"

#include <utility>
#include <vector>

#include <sys/socket.h>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <google/protobuf/message_lite.h>

namespace patchpanel {

MessageDispatcherInternal::MessageDispatcherInternal(base::ScopedFD fd)
    : fd_(std::move(fd)) {}

void MessageDispatcherInternal::RegisterFailureHandler(
    base::RepeatingCallback<void()> handler) {
  failure_handler_ = std::move(handler);
}

void MessageDispatcherInternal::RegisterMessageHandler(
    base::RepeatingCallback<void()> handler) {
  watcher_ =
      base::FileDescriptorWatcher::WatchReadable(fd_.get(), std::move(handler));
}

bool MessageDispatcherInternal::GetMessage(
    google::protobuf::MessageLite* proto) {
  char buffer[1024];
  ssize_t len = recvfrom(fd_.get(), buffer, sizeof(buffer), MSG_DONTWAIT,
                         nullptr, nullptr);
  // Don't stop watchers on these errors.
  if (len < 0 && (errno == EAGAIN || errno == EINTR)) {
    return false;
  }
  // Handle errors (len < 0) and graceful shutdowns (len == 0). Explicit 0-byte
  // messages are not supported and considered as graceful shutdown.
  if (len <= 0) {
    if (len == 0) {
      LOG(ERROR) << "Read failed: stopping watcher: socket closed";
    } else {
      PLOG(ERROR) << "Read failed: stopping watcher";
    }
    watcher_.reset();
    if (!failure_handler_.is_null()) {
      failure_handler_.Run();
    }
    return false;
  }

  proto->Clear();
  if (!proto->ParseFromArray(buffer, static_cast<int>(len))) {
    LOG(ERROR) << "Error parsing protobuf " << proto->GetTypeName();
    return false;
  }

  return true;
}

bool MessageDispatcherInternal::SendMessage(
    const google::protobuf::MessageLite& proto) {
  if (!proto.IsInitialized()) {
    LOG(DFATAL) << "protobuf missing mandatory fields";
    return false;
  }
  std::string str;
  if (!proto.SerializeToString(&str)) {
    LOG(ERROR) << "error serializing protobuf";
    return false;
  }
  ssize_t len = write(fd_.get(), str.data(), str.size());
  if (len < 0) {
    PLOG(ERROR) << "write failed";
    return false;
  }
  if (len != static_cast<ssize_t>(str.size())) {
    LOG(ERROR) << "short write on protobuf";
    return false;
  }
  return true;
}

}  // namespace patchpanel
