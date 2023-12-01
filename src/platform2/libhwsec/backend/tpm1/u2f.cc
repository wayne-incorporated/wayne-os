// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/u2f.h"

#include <cstdint>
#include <optional>

#include <brillo/secure_blob.h>

#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

using u2f::ConsumeMode;
using u2f::GenerateResult;
using u2f::Signature;
using u2f::UserPresenceMode;

StatusOr<bool> U2fTpm1::IsEnabled() {
  return false;
}

StatusOr<GenerateResult> U2fTpm1::GenerateUserPresenceOnly(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    ConsumeMode consume_mode,
    UserPresenceMode up_mode) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

StatusOr<GenerateResult> U2fTpm1::Generate(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    ConsumeMode consume_mode,
    UserPresenceMode up_mode,
    const brillo::Blob& auth_time_secret_hash) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

StatusOr<Signature> U2fTpm1::SignUserPresenceOnly(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const brillo::Blob& hash_to_sign,
    ConsumeMode consume_mode,
    UserPresenceMode up_mode,
    const brillo::Blob& key_handle) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

StatusOr<Signature> U2fTpm1::Sign(
    const brillo::Blob& app_id,
    const brillo::SecureBlob& user_secret,
    const std::optional<brillo::SecureBlob>& auth_time_secret,
    const brillo::Blob& hash_to_sign,
    ConsumeMode consume_mode,
    UserPresenceMode up_mode,
    const brillo::Blob& key_handle) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

Status U2fTpm1::CheckUserPresenceOnly(const brillo::Blob& app_id,
                                      const brillo::SecureBlob& user_secret,
                                      const brillo::Blob& key_handle) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

Status U2fTpm1::Check(const brillo::Blob& app_id,
                      const brillo::SecureBlob& user_secret,
                      const brillo::Blob& key_handle) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

StatusOr<Signature> U2fTpm1::G2fAttest(const brillo::Blob& app_id,
                                       const brillo::SecureBlob& user_secret,
                                       const brillo::Blob& challenge,
                                       const brillo::Blob& key_handle,
                                       const brillo::Blob& public_key) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

StatusOr<brillo::Blob> U2fTpm1::GetG2fAttestData(
    const brillo::Blob& app_id,
    const brillo::Blob& challenge,
    const brillo::Blob& key_handle,
    const brillo::Blob& public_key) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

StatusOr<Signature> U2fTpm1::CorpAttest(const brillo::Blob& app_id,
                                        const brillo::SecureBlob& user_secret,
                                        const brillo::Blob& challenge,
                                        const brillo::Blob& key_handle,
                                        const brillo::Blob& public_key,
                                        const brillo::Blob& salt) {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

StatusOr<u2f::Config> U2fTpm1::GetConfig() {
  return MakeStatus<TPMError>("Unsupported", TPMRetryAction::kNoRetry);
}

}  // namespace hwsec
