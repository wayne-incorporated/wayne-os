// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HERMES_ADAPTOR_FACTORY_H_
#define HERMES_ADAPTOR_FACTORY_H_

#include <memory>

#include "hermes/adaptor_factory_interface.h"

namespace hermes {

class AdaptorFactory : public AdaptorFactoryInterface {
 public:
  std::unique_ptr<EuiccAdaptorInterface> CreateEuiccAdaptor(
      Euicc* euicc) override;
  std::unique_ptr<ManagerAdaptorInterface> CreateManagerAdaptor(
      Manager* manager) override;
};

}  // namespace hermes

#endif  // HERMES_ADAPTOR_FACTORY_H_
