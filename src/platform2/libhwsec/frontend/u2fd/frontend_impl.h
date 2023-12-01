// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_U2FD_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_U2FD_FRONTEND_IMPL_H_

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/frontend/u2fd/frontend.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

class U2fFrontendImpl : public U2fFrontend, public FrontendImpl {
 public:
  using FrontendImpl::FrontendImpl;
  ~U2fFrontendImpl() override = default;

  StatusOr<bool> IsEnabled() const override;
  StatusOr<bool> IsReady() const override;
  StatusOr<CreateKeyResult> GenerateRSASigningKey(
      const brillo::SecureBlob& auth_value) const override;
  StatusOr<RSAPublicInfo> GetRSAPublicKey(Key key) const override;
  StatusOr<ScopedKey> LoadKey(
      const brillo::Blob& key_blob,
      const brillo::SecureBlob& auth_value) const override;
  StatusOr<brillo::Blob> RSASign(Key key,
                                 const brillo::Blob& data) const override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_U2FD_FRONTEND_IMPL_H_
