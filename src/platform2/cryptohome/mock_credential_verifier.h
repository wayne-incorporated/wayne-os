// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_CREDENTIAL_VERIFIER_H_
#define CRYPTOHOME_MOCK_CREDENTIAL_VERIFIER_H_

#include <string>
#include <utility>

#include <gmock/gmock.h>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/key_objects.h"

namespace cryptohome {

class MockCredentialVerifier : public SyncCredentialVerifier {
 public:
  using SyncCredentialVerifier::SyncCredentialVerifier;

  MockCredentialVerifier(const MockCredentialVerifier&) = delete;
  MockCredentialVerifier& operator=(const MockCredentialVerifier&) = delete;

  MOCK_METHOD(CryptohomeStatus,
              VerifySync,
              (const AuthInput&),
              (const, override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_CREDENTIAL_VERIFIER_H_
