// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/frontend/pinweaver/frontend_impl.h"

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/backend/backend.h"
#include "libhwsec/middleware/middleware.h"
#include "libhwsec/status.h"

using hwsec_foundation::status::MakeStatus;

namespace hwsec {

using CredentialTreeResult = PinWeaverFrontend::CredentialTreeResult;
using GetLogResult = PinWeaverFrontend::GetLogResult;
using ReplayLogOperationResult = PinWeaverFrontend::ReplayLogOperationResult;
using DelaySchedule = PinWeaverFrontend::DelaySchedule;
using PinWeaverEccPoint = Backend::PinWeaver::PinWeaverEccPoint;

StatusOr<bool> PinWeaverFrontendImpl::IsEnabled() const {
  return middleware_.CallSync<&Backend::PinWeaver::IsEnabled>();
}

StatusOr<uint8_t> PinWeaverFrontendImpl::GetVersion() const {
  return middleware_.CallSync<&Backend::PinWeaver::GetVersion>();
}

StatusOr<CredentialTreeResult> PinWeaverFrontendImpl::Reset(
    uint32_t bits_per_level, uint32_t length_labels) const {
  return middleware_.CallSync<&Backend::PinWeaver::Reset>(bits_per_level,
                                                          length_labels);
}

StatusOr<CredentialTreeResult> PinWeaverFrontendImpl::InsertCredential(
    const std::vector<OperationPolicySetting>& policies,
    const uint64_t label,
    const std::vector<brillo::Blob>& h_aux,
    const brillo::SecureBlob& le_secret,
    const brillo::SecureBlob& he_secret,
    const brillo::SecureBlob& reset_secret,
    const DelaySchedule& delay_schedule,
    std::optional<uint32_t> expiration_delay) const {
  return middleware_.CallSync<&Backend::PinWeaver::InsertCredential>(
      policies, label, h_aux, le_secret, he_secret, reset_secret,
      delay_schedule, expiration_delay);
}

StatusOr<CredentialTreeResult> PinWeaverFrontendImpl::CheckCredential(
    const uint64_t label,
    const std::vector<brillo::Blob>& h_aux,
    const brillo::Blob& orig_cred_metadata,
    const brillo::SecureBlob& le_secret) const {
  return middleware_.CallSync<&Backend::PinWeaver::CheckCredential>(
      label, h_aux, orig_cred_metadata, le_secret);
}

StatusOr<CredentialTreeResult> PinWeaverFrontendImpl::RemoveCredential(
    const uint64_t label,
    const std::vector<std::vector<uint8_t>>& h_aux,
    const std::vector<uint8_t>& mac) const {
  return middleware_.CallSync<&Backend::PinWeaver::RemoveCredential>(
      label, h_aux, mac);
}

StatusOr<CredentialTreeResult> PinWeaverFrontendImpl::ResetCredential(
    const uint64_t label,
    const std::vector<std::vector<uint8_t>>& h_aux,
    const std::vector<uint8_t>& orig_cred_metadata,
    const brillo::SecureBlob& reset_secret,
    bool strong_reset) const {
  return middleware_.CallSync<&Backend::PinWeaver::ResetCredential>(
      label, h_aux, orig_cred_metadata, reset_secret, strong_reset);
}

StatusOr<GetLogResult> PinWeaverFrontendImpl::GetLog(
    const std::vector<uint8_t>& cur_disk_root_hash) const {
  return middleware_.CallSync<&Backend::PinWeaver::GetLog>(cur_disk_root_hash);
}

StatusOr<ReplayLogOperationResult> PinWeaverFrontendImpl::ReplayLogOperation(
    const brillo::Blob& log_entry_root,
    const std::vector<brillo::Blob>& h_aux,
    const brillo::Blob& orig_cred_metadata) const {
  return middleware_.CallSync<&Backend::PinWeaver::ReplayLogOperation>(
      log_entry_root, h_aux, orig_cred_metadata);
}

StatusOr<int> PinWeaverFrontendImpl::GetWrongAuthAttempts(
    const brillo::Blob& cred_metadata) const {
  return middleware_.CallSync<&Backend::PinWeaver::GetWrongAuthAttempts>(
      cred_metadata);
}

StatusOr<DelaySchedule> PinWeaverFrontendImpl::GetDelaySchedule(
    const brillo::Blob& cred_metadata) const {
  return middleware_.CallSync<&Backend::PinWeaver::GetDelaySchedule>(
      cred_metadata);
}

StatusOr<uint32_t> PinWeaverFrontendImpl::GetDelayInSeconds(
    const brillo::Blob& cred_metadata) const {
  return middleware_.CallSync<&Backend::PinWeaver::GetDelayInSeconds>(
      cred_metadata);
}

StatusOr<std::optional<uint32_t>> PinWeaverFrontendImpl::GetExpirationInSeconds(
    const brillo::Blob& cred_metadata) const {
  return middleware_.CallSync<&Backend::PinWeaver::GetExpirationInSeconds>(
      cred_metadata);
}

StatusOr<PinWeaverEccPoint> PinWeaverFrontendImpl::GeneratePk(
    uint8_t auth_channel, const PinWeaverEccPoint& client_public_key) const {
  return middleware_.CallSync<&Backend::PinWeaver::GeneratePk>(
      auth_channel, client_public_key);
}

StatusOr<CredentialTreeResult> PinWeaverFrontendImpl::InsertRateLimiter(
    uint8_t auth_channel,
    const std::vector<OperationPolicySetting>& policies,
    const uint64_t label,
    const std::vector<brillo::Blob>& h_aux,
    const brillo::SecureBlob& reset_secret,
    const DelaySchedule& delay_schedule,
    std::optional<uint32_t> expiration_delay) const {
  return middleware_.CallSync<&Backend::PinWeaver::InsertRateLimiter>(
      auth_channel, policies, label, h_aux, reset_secret, delay_schedule,
      expiration_delay);
}

StatusOr<CredentialTreeResult> PinWeaverFrontendImpl::StartBiometricsAuth(
    uint8_t auth_channel,
    const uint64_t label,
    const std::vector<brillo::Blob>& h_aux,
    const brillo::Blob& orig_cred_metadata,
    const brillo::Blob& client_nonce) const {
  return middleware_.CallSync<&Backend::PinWeaver::StartBiometricsAuth>(
      auth_channel, label, h_aux, orig_cred_metadata, client_nonce);
}

Status PinWeaverFrontendImpl::BlockGeneratePk() const {
  return middleware_.CallSync<&Backend::PinWeaver::BlockGeneratePk>();
}

}  // namespace hwsec
