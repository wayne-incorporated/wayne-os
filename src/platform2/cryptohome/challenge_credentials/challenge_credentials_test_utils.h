// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_TEST_UTILS_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_TEST_UTILS_H_

#include <memory>
#include <string>

#include <brillo/secure_blob.h>

#include "cryptohome/challenge_credentials/challenge_credentials_helper.h"

namespace cryptohome {

class Credentials;

// Functions that make callbacks for ChallengeCredentialsHelper that store the
// result into the given smart pointer (this smart pointer will become non-null
// after the callback gets executed):

// for ChallengeCredentialsHelper::GenerateNew():
ChallengeCredentialsHelper::GenerateNewCallback
MakeChallengeCredentialsGenerateNewResultWriter(
    std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>*
        result);

// for ChallengeCredentialsHelper::Decrypt():
ChallengeCredentialsHelper::DecryptCallback
MakeChallengeCredentialsDecryptResultWriter(
    std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>*
        result);

// Functions that verify that the result returned from the
// ChallengeCredentialsHelper operation is valid:

// for ChallengeCredentialsHelper::GenerateNew():
void VerifySuccessfulChallengeCredentialsGenerateNewResult(
    const ChallengeCredentialsHelper::GenerateNewOrDecryptResult& result,
    const brillo::SecureBlob& expected_passkey);

// for ChallengeCredentialsHelper::Decrypt():
void VerifySuccessfulChallengeCredentialsDecryptResult(
    const ChallengeCredentialsHelper::GenerateNewOrDecryptResult& result,
    const brillo::SecureBlob& expected_passkey);

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_CHALLENGE_CREDENTIALS_TEST_UTILS_H_
