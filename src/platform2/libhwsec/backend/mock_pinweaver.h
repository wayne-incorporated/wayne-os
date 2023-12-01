// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_BACKEND_MOCK_PINWEAVER_H_
#define LIBHWSEC_BACKEND_MOCK_PINWEAVER_H_

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec/backend/pinweaver.h"
#include "libhwsec/status.h"

namespace hwsec {

class MockPinWeaver : public PinWeaver {
 public:
  MockPinWeaver() = default;
  explicit MockPinWeaver(PinWeaver* on_call) : default_(on_call) {
    using testing::Invoke;
    if (!default_)
      return;
    ON_CALL(*this, IsEnabled)
        .WillByDefault(Invoke(default_, &PinWeaver::IsEnabled));
    ON_CALL(*this, GetVersion)
        .WillByDefault(Invoke(default_, &PinWeaver::GetVersion));
    ON_CALL(*this, Reset).WillByDefault(Invoke(default_, &PinWeaver::Reset));
    ON_CALL(*this, InsertCredential)
        .WillByDefault(Invoke(default_, &PinWeaver::InsertCredential));
    ON_CALL(*this, CheckCredential)
        .WillByDefault(Invoke(default_, &PinWeaver::CheckCredential));
    ON_CALL(*this, RemoveCredential)
        .WillByDefault(Invoke(default_, &PinWeaver::RemoveCredential));
    ON_CALL(*this, ResetCredential)
        .WillByDefault(Invoke(default_, &PinWeaver::ResetCredential));
    ON_CALL(*this, GetLog).WillByDefault(Invoke(default_, &PinWeaver::GetLog));
    ON_CALL(*this, ReplayLogOperation)
        .WillByDefault(Invoke(default_, &PinWeaver::ReplayLogOperation));
    ON_CALL(*this, GetWrongAuthAttempts)
        .WillByDefault(Invoke(default_, &PinWeaver::GetWrongAuthAttempts));
    ON_CALL(*this, GetDelaySchedule)
        .WillByDefault(Invoke(default_, &PinWeaver::GetDelaySchedule));
    ON_CALL(*this, GetDelayInSeconds)
        .WillByDefault(Invoke(default_, &PinWeaver::GetDelayInSeconds));
    ON_CALL(*this, GetExpirationInSeconds)
        .WillByDefault(Invoke(default_, &PinWeaver::GetExpirationInSeconds));
    ON_CALL(*this, GeneratePk)
        .WillByDefault(Invoke(default_, &PinWeaver::GeneratePk));
    ON_CALL(*this, InsertRateLimiter)
        .WillByDefault(Invoke(default_, &PinWeaver::InsertRateLimiter));
    ON_CALL(*this, StartBiometricsAuth)
        .WillByDefault(Invoke(default_, &PinWeaver::StartBiometricsAuth));
    ON_CALL(*this, BlockGeneratePk)
        .WillByDefault(Invoke(default_, &PinWeaver::BlockGeneratePk));
  }

  MOCK_METHOD(StatusOr<bool>, IsEnabled, (), (override));
  MOCK_METHOD(StatusOr<uint8_t>, GetVersion, (), (override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              Reset,
              (uint32_t bits_per_level, uint32_t length_labels),
              (override));
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
              (override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              CheckCredential,
              (const uint64_t label,
               const std::vector<brillo::Blob>& h_aux,
               const brillo::Blob& orig_cred_metadata,
               const brillo::SecureBlob& le_secret),
              (override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              RemoveCredential,
              (const uint64_t label,
               const std::vector<std::vector<uint8_t>>& h_aux,
               const std::vector<uint8_t>& mac),
              (override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              ResetCredential,
              (const uint64_t label,
               const std::vector<std::vector<uint8_t>>& h_aux,
               const std::vector<uint8_t>& orig_cred_metadata,
               const brillo::SecureBlob& reset_secret,
               bool strong_reset),
              (override));
  MOCK_METHOD(StatusOr<GetLogResult>,
              GetLog,
              (const std::vector<uint8_t>& cur_disk_root_hash),
              (override));
  MOCK_METHOD(StatusOr<ReplayLogOperationResult>,
              ReplayLogOperation,
              (const brillo::Blob& log_entry_root,
               const std::vector<brillo::Blob>& h_aux,
               const brillo::Blob& orig_cred_metadata),
              (override));
  MOCK_METHOD(StatusOr<int>,
              GetWrongAuthAttempts,
              (const brillo::Blob& cred_metadata),
              (override));
  MOCK_METHOD(StatusOr<DelaySchedule>,
              GetDelaySchedule,
              (const brillo::Blob& cred_metadata),
              (override));
  MOCK_METHOD(StatusOr<uint32_t>,
              GetDelayInSeconds,
              (const brillo::Blob& cred_metadata),
              (override));
  MOCK_METHOD(StatusOr<std::optional<uint32_t>>,
              GetExpirationInSeconds,
              (const brillo::Blob& cred_metadata),
              (override));
  MOCK_METHOD(StatusOr<PinWeaverEccPoint>,
              GeneratePk,
              (uint8_t auth_channel,
               const PinWeaverEccPoint& client_public_key),
              (override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              InsertRateLimiter,
              (uint8_t auth_channel,
               const std::vector<OperationPolicySetting>& policies,
               const uint64_t label,
               const std::vector<brillo::Blob>& h_aux,
               const brillo::SecureBlob& reset_secret,
               const DelaySchedule& delay_schedule,
               std::optional<uint32_t> expiration_delay),
              (override));
  MOCK_METHOD(StatusOr<CredentialTreeResult>,
              StartBiometricsAuth,
              (uint8_t auth_channel,
               const uint64_t label,
               const std::vector<brillo::Blob>& h_aux,
               const brillo::Blob& orig_cred_metadata,
               const brillo::Blob& client_nonce),
              (override));
  MOCK_METHOD(Status, BlockGeneratePk, (), (override));

 private:
  PinWeaver* default_;
};

}  // namespace hwsec

#endif  // LIBHWSEC_BACKEND_MOCK_PINWEAVER_H_
