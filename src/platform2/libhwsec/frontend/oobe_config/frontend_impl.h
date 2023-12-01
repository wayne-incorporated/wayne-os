// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_OOBE_CONFIG_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_OOBE_CONFIG_FRONTEND_IMPL_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/frontend/oobe_config/frontend.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class OobeConfigFrontendImpl : public OobeConfigFrontend, public FrontendImpl {
 public:
  using FrontendImpl::FrontendImpl;
  ~OobeConfigFrontendImpl() override = default;

  Status IsRollbackSpaceReady() const override;
  Status ResetRollbackSpace() const override;
  StatusOr<brillo::Blob> Encrypt(
      const brillo::SecureBlob& plain_data) const override;
  StatusOr<brillo::SecureBlob> Decrypt(
      const brillo::Blob& encrypted_data) const override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_OOBE_CONFIG_FRONTEND_IMPL_H_
