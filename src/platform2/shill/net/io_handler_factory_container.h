// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_IO_HANDLER_FACTORY_CONTAINER_H_
#define SHILL_NET_IO_HANDLER_FACTORY_CONTAINER_H_

#include <memory>

#include <base/no_destructor.h>

#include "shill/net/io_handler_factory.h"

namespace shill {

// By default, this container will use the IOHandlerFactory that uses
// libbase's FileDescriptorWatcher. The caller can implement their own
// IOHandlerFactory and overwrite the default using SetIOHandlerFactory.
class SHILL_EXPORT IOHandlerFactoryContainer {
 public:
  virtual ~IOHandlerFactoryContainer();

  // This is a singleton. Use IOHandlerFactoryContainer::GetInstance()->Foo().
  static IOHandlerFactoryContainer* GetInstance();

  // Update the default IOHandlerFactory for creating IOHandlers. This
  // container will assume the ownership of the passed in |factory|.
  void SetIOHandlerFactory(IOHandlerFactory* factory);

  IOHandlerFactory* GetIOHandlerFactory();

 protected:
  IOHandlerFactoryContainer();
  IOHandlerFactoryContainer(const IOHandlerFactoryContainer&) = delete;
  IOHandlerFactoryContainer& operator=(const IOHandlerFactoryContainer&) =
      delete;

 private:
  friend class base::NoDestructor<IOHandlerFactoryContainer>;
  std::unique_ptr<IOHandlerFactory> factory_;
};

}  // namespace shill

#endif  // SHILL_NET_IO_HANDLER_FACTORY_CONTAINER_H_
