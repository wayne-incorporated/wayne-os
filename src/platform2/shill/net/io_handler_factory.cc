// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/io_handler_factory.h"

#include "shill/net/io_input_handler.h"
#include "shill/net/io_ready_handler.h"

namespace shill {

// static
IOHandlerFactory* IOHandlerFactory::GetInstance() {
  static base::NoDestructor<IOHandlerFactory> instance;
  return instance.get();
}

IOHandlerFactory::IOHandlerFactory() = default;
IOHandlerFactory::~IOHandlerFactory() = default;

IOHandler* IOHandlerFactory::CreateIOInputHandler(
    int fd,
    const IOHandler::InputCallback& input_callback,
    const IOHandler::ErrorCallback& error_callback) {
  IOHandler* handler = new IOInputHandler(fd, input_callback, error_callback);
  handler->Start();
  return handler;
}

IOHandler* IOHandlerFactory::CreateIOReadyHandler(
    int fd,
    IOHandler::ReadyMode mode,
    const IOHandler::ReadyCallback& ready_callback) {
  IOHandler* handler = new IOReadyHandler(fd, mode, ready_callback);
  handler->Start();
  return handler;
}

}  // namespace shill
