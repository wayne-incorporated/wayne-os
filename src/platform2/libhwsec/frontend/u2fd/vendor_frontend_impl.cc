// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/u2fd/vendor_frontend_impl.h"

#include <brillo/secure_blob.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/space.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

StatusOr<bool> U2fVendorFrontendImpl::IsEnabled() const {
  return middleware_.CallSync<&Backend::U2f::IsEnabled>();
}

StatusOr<u2f::GenerateResult> U2fVendorFrontendImpl::GenerateUserPresenceOnly(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    u2f::ConsumeMode consume_mode,
    u2f::UserPresenceMode up_mode) const {
  return middleware_.CallSync<&Backend::U2f::GenerateUserPresenceOnly>(
      app_id, user_secret, consume_mode, up_mode);
}

StatusOr<u2f::GenerateResult> U2fVendorFrontendImpl::Generate(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    u2f::ConsumeMode consume_mode,
    u2f::UserPresenceMode up_mode,
    const brillo::Blob& auth_time_secret_hash) const {
  return middleware_.CallSync<&Backend::U2f::Generate>(
      app_id, user_secret, consume_mode, up_mode, auth_time_secret_hash);
}

StatusOr<u2f::Signature> U2fVendorFrontendImpl::SignUserPresenceOnly(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const brillo::Blob& hash_to_sign,
    u2f::ConsumeMode consume_mode,
    u2f::UserPresenceMode up_mode,
    const brillo::Blob& key_handle) const {
  return middleware_.CallSync<&Backend::U2f::SignUserPresenceOnly>(
      app_id, user_secret, hash_to_sign, consume_mode, up_mode, key_handle);
}

StatusOr<u2f::Signature> U2fVendorFrontendImpl::Sign(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const std::optional<brillo::SecureBlob>& auth_time_secret,
    const brillo::Blob& hash_to_sign,
    u2f::ConsumeMode consume_mode,
    u2f::UserPresenceMode up_mode,
    const brillo::Blob& key_handle) const {
  return middleware_.CallSync<&Backend::U2f::Sign>(
      app_id, user_secret, auth_time_secret, hash_to_sign, consume_mode,
      up_mode, key_handle);
}

Status U2fVendorFrontendImpl::CheckUserPresenceOnly(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const brillo::Blob& key_handle) const {
  return middleware_.CallSync<&Backend::U2f::CheckUserPresenceOnly>(
      app_id, user_secret, key_handle);
}

Status U2fVendorFrontendImpl::Check(const brillo::Blob& app_id,
                                    const brillo::SecureBlob& user_secret,
                                    const brillo::Blob& key_handle) const {
  return middleware_.CallSync<&Backend::U2f::Check>(app_id, user_secret,
                                                    key_handle);
}

StatusOr<u2f::Signature> U2fVendorFrontendImpl::G2fAttest(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const brillo::Blob& challenge,
    const brillo::Blob& key_handle,
    const brillo::Blob& public_key) const {
  return middleware_.CallSync<&Backend::U2f::G2fAttest>(
      app_id, user_secret, challenge, key_handle, public_key);
}

StatusOr<brillo::Blob> U2fVendorFrontendImpl::GetG2fAttestData(
    const brillo::Blob& app_id,
    const brillo::Blob& challenge,
    const brillo::Blob& key_handle,
    const brillo::Blob& public_key) const {
  return middleware_.CallSync<&Backend::U2f::GetG2fAttestData>(
      app_id, challenge, key_handle, public_key);
}

StatusOr<u2f::Signature> U2fVendorFrontendImpl::CorpAttest(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const brillo::Blob& challenge,
    const brillo::Blob& key_handle,
    const brillo::Blob& public_key,
    const brillo::Blob& salt) const {
  return middleware_.CallSync<&Backend::U2f::CorpAttest>(
      app_id, user_secret, challenge, key_handle, public_key, salt);
}

StatusOr<brillo::Blob> U2fVendorFrontendImpl::GetG2fCert() const {
  ASSIGN_OR_RETURN(
      bool is_ready,
      middleware_.CallSync<&Backend::RoData::IsReady>(RoSpace::kG2fCert),
      _.WithStatus<TPMError>("NV space not ready"));
  if (!is_ready) {
    return MakeStatus<TPMError>("NV space not ready", TPMRetryAction::kNoRetry);
  }
  return middleware_.CallSync<&Backend::RoData::Read>(RoSpace::kG2fCert);
}

StatusOr<U2fVendorFrontendImpl::RwVersion> U2fVendorFrontendImpl::GetRwVersion()
    const {
  return middleware_.CallSync<&Backend::Vendor::GetRwVersion>();
}

StatusOr<u2f::Config> U2fVendorFrontendImpl::GetConfig() const {
  return middleware_.CallSync<&Backend::U2f::GetConfig>();
}

}  // namespace hwsec
