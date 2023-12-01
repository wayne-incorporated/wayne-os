// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_MOCK_CHALLENGE_CREDENTIALS_HELPER_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_MOCK_CHALLENGE_CREDENTIALS_HELPER_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"
#include "cryptohome/key_challenge_service.h"

namespace cryptohome {

class MockChallengeCredentialsHelper : public ChallengeCredentialsHelper {
 public:
  MockChallengeCredentialsHelper() = default;
  ~MockChallengeCredentialsHelper() = default;

  MOCK_METHOD(void,
              GenerateNew,
              (const Username& account_id,
               const structure::ChallengePublicKeyInfo& public_key_info,
               const ObfuscatedUsername& obfuscated_username,
               std::unique_ptr<KeyChallengeService> key_challenge_service,
               GenerateNewCallback callback),
              (override));
  MOCK_METHOD(void,
              Decrypt,
              (const Username& account_id,
               const structure::ChallengePublicKeyInfo& public_key_info,
               const structure::SignatureChallengeInfo& keyset_challenge_info,
               std::unique_ptr<KeyChallengeService> key_challenge_service,
               DecryptCallback callback),
              (override));
  MOCK_METHOD(void,
              VerifyKey,
              (const Username& account_id,
               const structure::ChallengePublicKeyInfo& public_key_info,
               std::unique_ptr<KeyChallengeService> key_challenge_service,
               VerifyKeyCallback callback),
              (override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_MOCK_CHALLENGE_CREDENTIALS_HELPER_H_
