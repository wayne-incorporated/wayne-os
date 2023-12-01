// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FRONTEND_PINWEAVER_MOCK_FRONTEND_H_
#define LIBHWSEC_FRONTEND_PINWEAVER_MOCK_FRONTEND_H_

#include <vector>

#include <absl/container/flat_hash_set.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "libhwsec/frontend/mock_frontend.h"
#include "libhwsec/frontend/pinweaver/frontend.h"

namespace hwsec {

class MockPinWeaverFrontend : public MockFrontend, public PinWeaverFrontend {
 public:
  MockPinWeaverFrontend() = default;
  ~MockPinWeaverFrontend() override = default;

  MOCK_METHOD(StatusOr<bool>, IsEnabled, (), (const override));
  MOCK_METHOD(StatusOr<uint8_t>, GetVersion, (), (const override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              Reset,
              (uint32_t bits_per_level, uint32_t length_labels),
              (const override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              InsertCredential,
              (const std::vector<OperationPolicySetting>& policies,
               const uint64_t label,
               const std::vector<brillo::Blob>& h_aux,
               const brillo::SecureBlob& le_secret,
               const brillo::SecureBlob& he_secret,
               const brillo::SecureBlob& reset_secret,
               const DelaySchedule& delay_schedule,
               std::optional<uint32_t> expiration_delay),
              (const override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              CheckCredential,
              (const uint64_t label,
               const std::vector<brillo::Blob>& h_aux,
               const brillo::Blob& orig_cred_metadata,
               const brillo::SecureBlob& le_secret),
              (const override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              RemoveCredential,
              (const uint64_t label,
               const std::vector<std::vector<uint8_t>>& h_aux,
               const std::vector<uint8_t>& mac),
              (const override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              ResetCredential,
              (const uint64_t label,
               const std::vector<std::vector<uint8_t>>& h_aux,
               const std::vector<uint8_t>& orig_cred_metadata,
               const brillo::SecureBlob& reset_secret,
               bool strong_reset),
              (const override));
  MOCK_METHOD(StatusOr<GetLogResult>,
              GetLog,
              (const std::vector<uint8_t>& cur_disk_root_hash),
              (const override));
  MOCK_METHOD(StatusOr<ReplayLogOperationResult>,
              ReplayLogOperation,
              (const brillo::Blob& log_entry_root,
               const std::vector<brillo::Blob>& h_aux,
               const brillo::Blob& orig_cred_metadata),
              (const override));
  MOCK_METHOD(StatusOr<int>,
              GetWrongAuthAttempts,
              (const brillo::Blob& cred_metadata),
              (const override));
  MOCK_METHOD(StatusOr<DelaySchedule>,
              GetDelaySchedule,
              (const brillo::Blob& cred_metadata),
              (const override));
  MOCK_METHOD(StatusOr<uint32_t>,
              GetDelayInSeconds,
              (const brillo::Blob& cred_metadata),
              (const override));
  MOCK_METHOD(StatusOr<std::optional<uint32_t>>,
              GetExpirationInSeconds,
              (const brillo::Blob& cred_metadata),
              (const override));
  MOCK_METHOD(StatusOr<PinWeaverEccPoint>,
              GeneratePk,
              (uint8_t auth_channel,
               const PinWeaverEccPoint& client_public_key),
              (const override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              InsertRateLimiter,
              (uint8_t auth_channel,
               const std::vector<OperationPolicySetting>& policies,
               const uint64_t label,
               const std::vector<brillo::Blob>& h_aux,
               const brillo::SecureBlob& reset_secret,
               const DelaySchedule& delay_schedule,
               std::optional<uint32_t> expiration_delay),
              (const override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              StartBiometricsAuth,
              (uint8_t auth_channel,
               const uint64_t label,
               const std::vector<brillo::Blob>& h_aux,
               const brillo::Blob& orig_cred_metadata,
               const brillo::Blob& client_nonce),
              (const override));
  MOCK_METHOD(Status, BlockGeneratePk, (), (const override));
};

}  // namespace hwsec

#endif  // LIBHWSEC_FRONTEND_PINWEAVER_MOCK_FRONTEND_H_
