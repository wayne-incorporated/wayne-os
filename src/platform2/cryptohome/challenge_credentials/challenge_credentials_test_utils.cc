// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/challenge_credentials/challenge_credentials_test_utils.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using brillo::Blob;
using brillo::SecureBlob;

namespace cryptohome {

ChallengeCredentialsHelper::GenerateNewCallback
MakeChallengeCredentialsGenerateNewResultWriter(
    std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>*
        result) {
  DCHECK(!*result);
  return base::BindOnce(
      [](std::unique_ptr<
             ChallengeCredentialsHelper::GenerateNewOrDecryptResult>* result,
         CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
             returned) {
        ASSERT_FALSE(*result);
        if (returned.ok()) {
          ChallengeCredentialsHelper::GenerateNewOrDecryptResult returned_val =
              std::move(returned).value();
          *result = std::make_unique<
              ChallengeCredentialsHelper::GenerateNewOrDecryptResult>(
              returned_val.info(), returned_val.passkey());
        } else {
          *result = nullptr;
        }
      },
      base::Unretained(result));
}

ChallengeCredentialsHelper::DecryptCallback
MakeChallengeCredentialsDecryptResultWriter(
    std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>*
        result) {
  DCHECK(!*result);
  return base::BindOnce(
      [](std::unique_ptr<
             ChallengeCredentialsHelper::GenerateNewOrDecryptResult>* result,
         CryptoStatusOr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
             returned) {
        ASSERT_FALSE(*result);
        if (returned.ok()) {
          std::unique_ptr<brillo::SecureBlob> passkey =
              std::move(returned).value().passkey();
          *result = std::make_unique<
              ChallengeCredentialsHelper::GenerateNewOrDecryptResult>(
              nullptr, std::move(passkey));
        } else {
          *result = nullptr;
        }
      },
      base::Unretained(result));
}

void VerifySuccessfulChallengeCredentialsGenerateNewResult(
    const ChallengeCredentialsHelper::GenerateNewOrDecryptResult& result,
    const SecureBlob& expected_passkey) {
  ASSERT_TRUE(result.passkey());
  ASSERT_TRUE(result.info());
  EXPECT_EQ(expected_passkey, *result.passkey());
}

void VerifySuccessfulChallengeCredentialsDecryptResult(
    const ChallengeCredentialsHelper::GenerateNewOrDecryptResult& result,
    const SecureBlob& expected_passkey) {
  ASSERT_TRUE(result.passkey());
  EXPECT_EQ(expected_passkey, *result.passkey());
}

}  // namespace cryptohome
