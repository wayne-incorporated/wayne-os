// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/frontend_impl.h"

#include <memory>
#include <utility>

#include "libhwsec/middleware/middleware.h"
#include "libhwsec/middleware/middleware_derivative.h"

namespace hwsec {

FrontendImpl::FrontendImpl(MiddlewareDerivative middleware_derivative)
    : default_middleware_(
          std::make_unique<Middleware>(std::move(middleware_derivative))),
      middleware_(*default_middleware_) {}

FrontendImpl::~FrontendImpl() {}

}  // namespace hwsec
