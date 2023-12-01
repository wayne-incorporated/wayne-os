// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_IO_INPUT_HANDLER_H_
#define SHILL_NET_IO_INPUT_HANDLER_H_

#include <memory>

#include <base/files/file_descriptor_watcher_posix.h>

#include "shill/net/io_handler.h"

namespace shill {

// Monitor file descriptor for reading.
class IOInputHandler : public IOHandler {
 public:
  IOInputHandler(int fd,
                 const InputCallback& input_callback,
                 const ErrorCallback& error_callback);
  ~IOInputHandler();

  void Start() override;
  void Stop() override;

 private:
  void OnReadable();

  int fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
  InputCallback input_callback_;
  ErrorCallback error_callback_;
};

}  // namespace shill

#endif  // SHILL_NET_IO_INPUT_HANDLER_H_
