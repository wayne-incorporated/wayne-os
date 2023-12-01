// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_PINWEAVER_FRONTEND_IMPL_H_
#define LIBHWSEC_FRONTEND_PINWEAVER_FRONTEND_IMPL_H_

#include <optional>
#include <vector>

#include <brillo/secure_blob.h>

#include "libhwsec/frontend/frontend_impl.h"
#include "libhwsec/frontend/pinweaver/frontend.h"
#include "libhwsec/status.h"
#include "libhwsec/structures/operation_policy.h"

namespace hwsec {

class PinWeaverFrontendImpl : public PinWeaverFrontend, public FrontendImpl {
 public:
  using FrontendImpl::FrontendImpl;
  ~PinWeaverFrontendImpl() override = default;

  StatusOr<bool> IsEnabled() const override;
  StatusOr<uint8_t> GetVersion() const override;
  StatusOr<CredentialTreeResult> Reset(uint32_t bits_per_level,
                                       uint32_t length_labels) const override;
  StatusOr<CredentialTreeResult> InsertCredential(
      const std::vector<OperationPolicySetting>& policies,
      const uint64_t label,
      const std::vector<brillo::Blob>& h_aux,
      const brillo::SecureBlob& le_secret,
      const brillo::SecureBlob& he_secret,
      const brillo::SecureBlob& reset_secret,
      const DelaySchedule& delay_schedule,
      std::optional<uint32_t> expiration_delay) const override;
  StatusOr<CredentialTreeResult> CheckCredential(
      const uint64_t label,
      const std::vector<brillo::Blob>& h_aux,
      const brillo::Blob& orig_cred_metadata,
      const brillo::SecureBlob& le_secret) const override;
  StatusOr<CredentialTreeResult> RemoveCredential(
      const uint64_t label,
      const std::vector<std::vector<uint8_t>>& h_aux,
      const std::vector<uint8_t>& mac) const override;
  StatusOr<CredentialTreeResult> ResetCredential(
      const uint64_t label,
      const std::vector<std::vector<uint8_t>>& h_aux,
      const std::vector<uint8_t>& orig_cred_metadata,
      const brillo::SecureBlob& reset_secret,
      bool strong_reset) const override;
  StatusOr<GetLogResult> GetLog(
      const std::vector<uint8_t>& cur_disk_root_hash) const override;
  StatusOr<ReplayLogOperationResult> ReplayLogOperation(
      const brillo::Blob& log_entry_root,
      const std::vector<brillo::Blob>& h_aux,
      const brillo::Blob& orig_cred_metadata) const override;
  StatusOr<int> GetWrongAuthAttempts(
      const brillo::Blob& cred_metadata) const override;
  StatusOr<DelaySchedule> GetDelaySchedule(
      const brillo::Blob& cred_metadata) const override;
  StatusOr<uint32_t> GetDelayInSeconds(
      const brillo::Blob& cred_metadata) const override;
  StatusOr<std::optional<uint32_t>> GetExpirationInSeconds(
      const brillo::Blob& cred_metadata) const override;
  StatusOr<PinWeaverEccPoint> GeneratePk(
      uint8_t auth_channel,
      const PinWeaverEccPoint& client_public_key) const override;
  StatusOr<CredentialTreeResult> InsertRateLimiter(
      uint8_t auth_channel,
      const std::vector<OperationPolicySetting>& policies,
      const uint64_t label,
      const std::vector<brillo::Blob>& h_aux,
      const brillo::SecureBlob& reset_secret,
      const DelaySchedule& delay_schedule,
      std::optional<uint32_t> expiration_delay) const override;
  StatusOr<CredentialTreeResult> StartBiometricsAuth(
      uint8_t auth_channel,
      const uint64_t label,
      const std::vector<brillo::Blob>& h_aux,
      const brillo::Blob& orig_cred_metadata,
      const brillo::Blob& client_nonce) const override;
  Status BlockGeneratePk() const override;
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_PINWEAVER_FRONTEND_IMPL_H_
