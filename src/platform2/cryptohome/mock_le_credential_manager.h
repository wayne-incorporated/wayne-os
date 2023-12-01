// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_LE_CREDENTIAL_MANAGER_H_
#define CRYPTOHOME_MOCK_LE_CREDENTIAL_MANAGER_H_

#include "cryptohome/le_credential_manager.h"

#include <string>
#include <optional>
#include <vector>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

namespace cryptohome {

class MockLECredentialManager : public LECredentialManager {
 public:
  MOCK_METHOD(LECredStatus,
              InsertCredential,
              (const std::vector<hwsec::OperationPolicySetting>& policies,
               const brillo::SecureBlob&,
               const brillo::SecureBlob&,
               const brillo::SecureBlob&,
               const DelaySchedule&,
               std::optional<uint32_t>,
               uint64_t*),
              (override));

  MOCK_METHOD(LECredStatus,
              CheckCredential,
              (uint64_t,
               const brillo::SecureBlob&,
               brillo::SecureBlob*,
               brillo::SecureBlob*),
              (override));

  MOCK_METHOD(LECredStatus,
              ResetCredential,
              (uint64_t label,
               const brillo::SecureBlob& reset_secret,
               bool strong_reset),
              (override));

  MOCK_METHOD(LECredStatus, RemoveCredential, (uint64_t), (override));

  MOCK_METHOD(int, GetWrongAuthAttempts, (uint64_t label), (override));

  MOCK_METHOD(LECredStatusOr<uint32_t>,
              GetDelayInSeconds,
              (uint64_t label),
              (override));

  MOCK_METHOD(LECredStatusOr<std::optional<uint32_t>>,
              GetExpirationInSeconds,
              (uint64_t label),
              (override));

  MOCK_METHOD(LECredStatusOr<DelaySchedule>,
              GetDelaySchedule,
              (uint64_t label),
              (override));

  MOCK_METHOD(LECredStatus,
              InsertRateLimiter,
              (uint8_t,
               const std::vector<hwsec::OperationPolicySetting>&,
               const brillo::SecureBlob&,
               const DelaySchedule&,
               std::optional<uint32_t>,
               uint64_t*),
              (override));

  MOCK_METHOD(LECredStatusOr<LECredentialManager::StartBiometricsAuthReply>,
              StartBiometricsAuth,
              (uint8_t, uint64_t, const brillo::Blob&),
              (override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_LE_CREDENTIAL_MANAGER_H_
