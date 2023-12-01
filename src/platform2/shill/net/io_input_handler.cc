// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/io_input_handler.h"

#include <string>
#include <unistd.h>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace shill {

IOInputHandler::IOInputHandler(int fd,
                               const InputCallback& input_callback,
                               const ErrorCallback& error_callback)
    : fd_(fd),
      input_callback_(input_callback),
      error_callback_(error_callback) {}

IOInputHandler::~IOInputHandler() = default;

void IOInputHandler::Start() {
  watcher_ = base::FileDescriptorWatcher::WatchReadable(
      fd_,
      base::BindRepeating(&IOInputHandler::OnReadable, base::Unretained(this)));
  LOG_IF(ERROR, !watcher_) << "Failed on watching read";
}

void IOInputHandler::Stop() {
  watcher_ = nullptr;
}

void IOInputHandler::OnReadable() {
  unsigned char buf[IOHandler::kDataBufferSize];
  ssize_t len = read(fd_, buf, sizeof(buf));
  if (len < 0) {
    std::string condition = base::StringPrintf("File read error: %d", errno);
    LOG(ERROR) << condition;
    error_callback_.Run(condition);
  } else {
    InputData input_data(buf, len);
    input_callback_.Run(&input_data);
  }
}

}  // namespace shill
