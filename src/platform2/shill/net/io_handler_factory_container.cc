// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/net/io_handler_factory_container.h"

#include <base/check.h>
#include <base/logging.h>

namespace shill {

IOHandlerFactoryContainer::IOHandlerFactoryContainer()
    : factory_(new IOHandlerFactory()) {}

IOHandlerFactoryContainer::~IOHandlerFactoryContainer() = default;

IOHandlerFactoryContainer* IOHandlerFactoryContainer::GetInstance() {
  static base::NoDestructor<IOHandlerFactoryContainer> instance;
  return instance.get();
}

void IOHandlerFactoryContainer::SetIOHandlerFactory(IOHandlerFactory* factory) {
  CHECK(factory);
  factory_.reset(factory);
}

IOHandlerFactory* IOHandlerFactoryContainer::GetIOHandlerFactory() {
  return factory_.get();
}

}  // namespace shill
