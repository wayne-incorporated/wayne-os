// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_OPTEE_PLUGIN_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_OPTEE_PLUGIN_FRONTEND_IMPL_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/frontend/optee-plugin/frontend.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class OpteePluginFrontendImpl : public OpteePluginFrontend,
                                public FrontendImpl {
 public:
  using FrontendImpl::FrontendImpl;
  ~OpteePluginFrontendImpl() override = default;

  StatusOr<brillo::Blob> SendRawCommand(
      const brillo::Blob& command) const override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_OPTEE_PLUGIN_FRONTEND_IMPL_H_
