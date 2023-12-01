// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm2/backend_test_base.h"

#include <memory>
#include <utility>

#include <gtest/gtest.h>

#include "libhwsec/backend/tpm2/backend.h"
#include "libhwsec/error/tpm2_error.h"
#include "libhwsec/middleware/middleware_derivative.h"
#include "libhwsec/middleware/middleware_owner.h"
#include "libhwsec/proxy/proxy_for_test.h"
#include "libhwsec/status.h"

namespace hwsec {

BackendTpm2TestBase::BackendTpm2TestBase() = default;
BackendTpm2TestBase::~BackendTpm2TestBase() = default;

void BackendTpm2TestBase::SetUp() {
  proxy_ = std::make_unique<ProxyForTest>();

  auto backend = std::make_unique<BackendTpm2>(*proxy_, MiddlewareDerivative{});
  backend_ = backend.get();

  middleware_owner_ = std::make_unique<MiddlewareOwner>(
      std::move(backend), ThreadingMode::kCurrentThread);

  backend_->set_middleware_derivative_for_test(middleware_owner_->Derive());
}

}  // namespace hwsec
