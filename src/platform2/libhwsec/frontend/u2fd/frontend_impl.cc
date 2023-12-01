// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/u2fd/frontend_impl.h"

#include <utility>

#include <base/functional/callback.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/key.h"

namespace hwsec {

StatusOr<bool> U2fFrontendImpl::IsEnabled() const {
  return middleware_.CallSync<&Backend::State::IsEnabled>();
}

StatusOr<bool> U2fFrontendImpl::IsReady() const {
  return middleware_.CallSync<&Backend::State::IsReady>();
}

StatusOr<U2fFrontend::CreateKeyResult> U2fFrontendImpl::GenerateRSASigningKey(
    const brillo::SecureBlob& auth_value) const {
  return middleware_.CallSync<&Backend::KeyManagement::CreateKey>(
      OperationPolicySetting{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      KeyAlgoType::kRsa, KeyManagement::LoadKeyOptions{.auto_reload = true},
      Backend::KeyManagement::CreateKeyOptions{
          .allow_software_gen = false,
          .allow_decrypt = false,
          .allow_sign = true,
      });
}

StatusOr<RSAPublicInfo> U2fFrontendImpl::GetRSAPublicKey(Key key) const {
  return middleware_.CallSync<&Backend::KeyManagement::GetRSAPublicInfo>(key);
}

StatusOr<ScopedKey> U2fFrontendImpl::LoadKey(
    const brillo::Blob& key_blob, const brillo::SecureBlob& auth_value) const {
  return middleware_.CallSync<&Backend::KeyManagement::LoadKey>(
      OperationPolicy{
          .permission =
              Permission{
                  .auth_value = auth_value,
              },
      },
      key_blob, KeyManagement::LoadKeyOptions{.auto_reload = true});
}

StatusOr<brillo::Blob> U2fFrontendImpl::RSASign(
    Key key, const brillo::Blob& data) const {
  return middleware_.CallSync<&Backend::Signing::RawSign>(key, data,
                                                          SigningOptions{});
}

}  // namespace hwsec
