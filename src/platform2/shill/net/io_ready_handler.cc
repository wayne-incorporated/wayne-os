// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/io_ready_handler.h"

#include <unistd.h>

#include <base/functional/bind.h>
#include <base/logging.h>

namespace shill {

IOReadyHandler::IOReadyHandler(int fd,
                               ReadyMode mode,
                               const ReadyCallback& ready_callback)
    : fd_(fd), ready_mode_(mode), ready_callback_(ready_callback) {}

IOReadyHandler::~IOReadyHandler() = default;

void IOReadyHandler::Start() {
  switch (ready_mode_) {
    case kModeInput:
      watcher_ = base::FileDescriptorWatcher::WatchReadable(
          fd_, base::BindRepeating(ready_callback_, fd_));
      break;
    case kModeOutput:
      watcher_ = base::FileDescriptorWatcher::WatchWritable(
          fd_, base::BindRepeating(ready_callback_, fd_));
      break;
    default:
      LOG(FATAL) << "Unknown ready_mode_: " << ready_mode_;
  }

  LOG_IF(ERROR, !watcher_) << "Failed on watching fd";
}

void IOReadyHandler::Stop() {
  watcher_ = nullptr;
}

}  // namespace shill
