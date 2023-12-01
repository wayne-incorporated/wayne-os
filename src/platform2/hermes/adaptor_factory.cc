// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
#include <memory>

#include "hermes/adaptor_factory.h"
#include "hermes/euicc_dbus_adaptor.h"
#include "hermes/manager_dbus_adaptor.h"

namespace hermes {

std::unique_ptr<EuiccAdaptorInterface> AdaptorFactory::CreateEuiccAdaptor(
    Euicc* euicc) {
  return std::make_unique<EuiccDBusAdaptor>(euicc);
}

std::unique_ptr<ManagerAdaptorInterface> AdaptorFactory::CreateManagerAdaptor(
    Manager* manager) {
  return std::make_unique<ManagerDBusAdaptor>(manager);
}

}  // namespace hermes
