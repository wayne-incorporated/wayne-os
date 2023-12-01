// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_ADAPTOR_FACTORY_INTERFACE_H_
#define HERMES_ADAPTOR_FACTORY_INTERFACE_H_

#include <memory>

#include "hermes/adaptor_interfaces.h"
#include "hermes/dbus_bindings/org.chromium.Hermes.Manager.h"

namespace hermes {

class Euicc;
class Manager;

// Interface for an object factory that creates an adaptor/proxy object.
class AdaptorFactoryInterface {
 public:
  virtual ~AdaptorFactoryInterface() = default;
  virtual std::unique_ptr<EuiccAdaptorInterface> CreateEuiccAdaptor(
      Euicc* euicc) = 0;
  virtual std::unique_ptr<ManagerAdaptorInterface> CreateManagerAdaptor(
      Manager* manager) = 0;
};

}  // namespace hermes

#endif  // HERMES_ADAPTOR_FACTORY_INTERFACE_H_
