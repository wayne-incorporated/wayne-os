// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_IO_HANDLER_FACTORY_H_
#define SHILL_NET_IO_HANDLER_FACTORY_H_

#include <base/no_destructor.h>

#include "shill/net/io_handler.h"
#include "shill/net/shill_export.h"

namespace shill {

class SHILL_EXPORT IOHandlerFactory {
 public:
  static IOHandlerFactory* GetInstance();

  // TODO(benchan): Make constructor protected once all users of
  // IOHandlerFactory has been migrated to use IOHandlerFactory::GetInstance()
  // instead of constructing a new IOHandlerFactory.
  IOHandlerFactory();
  IOHandlerFactory(const IOHandlerFactory&) = delete;
  IOHandlerFactory& operator=(const IOHandlerFactory&) = delete;

  virtual ~IOHandlerFactory();

  virtual IOHandler* CreateIOInputHandler(
      int fd,
      const IOHandler::InputCallback& input_callback,
      const IOHandler::ErrorCallback& error_callback);

  virtual IOHandler* CreateIOReadyHandler(
      int fd,
      IOHandler::ReadyMode mode,
      const IOHandler::ReadyCallback& input_callback);

 private:
  friend class base::NoDestructor<IOHandlerFactory>;
};

}  // namespace shill

#endif  // SHILL_NET_IO_HANDLER_FACTORY_H_
