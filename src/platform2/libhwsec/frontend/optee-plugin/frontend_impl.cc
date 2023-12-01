// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/optee-plugin/frontend_impl.h"

#include <optional>
#include <utility>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<brillo::Blob> OpteePluginFrontendImpl::SendRawCommand(
    const brillo::Blob& command) const {
  return middleware_.CallSync<&Backend::Vendor::SendRawCommand>(command);
}

}  // namespace hwsec
