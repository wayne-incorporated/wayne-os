// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_FRONTEND_IMPL_H_

#include <memory>
#include <utility>

#include "libhwsec/frontend/frontend.h"
#include "libhwsec/middleware/middleware_derivative.h"

#ifndef BUILD_LIBHWSEC
#error "Don't include this file outside libhwsec!"
#endif

namespace hwsec {

// Forward declarations
class Middleware;

class FrontendImpl : public Frontend {
 public:
  explicit FrontendImpl(MiddlewareDerivative middleware_derivative);
  ~FrontendImpl() override;

 protected:
  std::unique_ptr<Middleware> default_middleware_;
  Middleware& middleware_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_FRONTEND_IMPL_H_
