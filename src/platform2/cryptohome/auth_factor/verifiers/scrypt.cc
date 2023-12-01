// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/verifiers/scrypt.h"

#include <memory>
#include <string>
#include <utility>

#include <base/logging.h>
#include <base/memory/ptr_util.h>
#include <brillo/secure_blob.h>
#include <brillo/secure_string.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <libhwsec-foundation/crypto/scrypt.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/auth_factor/auth_factor_metadata.h"
#include "cryptohome/auth_factor/auth_factor_type.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/error/location_utils.h"
#include "cryptohome/error/locations.h"
#include "cryptohome/key_objects.h"

namespace cryptohome {
namespace {

using ::cryptohome::error::CryptohomeError;
using ::cryptohome::error::ErrorActionSet;
using ::cryptohome::error::PossibleAction;
using ::cryptohome::error::PrimaryAction;
using ::hwsec_foundation::CreateSecureRandomBlob;
using ::hwsec_foundation::Scrypt;
using ::hwsec_foundation::status::MakeStatus;
using ::hwsec_foundation::status::OkStatus;

constexpr int kScryptNFactor = 1 << 12;  // 2^12
constexpr int kScryptRFactor = 8;
constexpr int kScryptPFactor = 1;
constexpr int kScryptSaltSize = 256 / CHAR_BIT;
constexpr int kScryptOutputSize = 256 / CHAR_BIT;

}  // namespace

std::unique_ptr<ScryptVerifier> ScryptVerifier::Create(
    std::string auth_factor_label, const brillo::SecureBlob& passkey) {
  // Create a salt and try to scrypt the passkey with it.
  brillo::SecureBlob scrypt_salt = CreateSecureRandomBlob(kScryptSaltSize);
  brillo::SecureBlob verifier(kScryptOutputSize, 0);
  if (Scrypt(passkey, scrypt_salt, kScryptNFactor, kScryptRFactor,
             kScryptPFactor, &verifier)) {
    return base::WrapUnique(new ScryptVerifier(std::move(auth_factor_label),
                                               std::move(scrypt_salt),
                                               std::move(verifier)));
  }
  // If the Scrypt failed, then we can't make a verifier with this passkey.
  return nullptr;
}

ScryptVerifier::ScryptVerifier(std::string auth_factor_label,
                               brillo::SecureBlob scrypt_salt,
                               brillo::SecureBlob verifier)
    : SyncCredentialVerifier(AuthFactorType::kPassword,
                             std::move(auth_factor_label),
                             {.metadata = auth_factor::PasswordMetadata()}),
      scrypt_salt_(std::move(scrypt_salt)),
      verifier_(std::move(verifier)) {}

CryptohomeStatus ScryptVerifier::VerifySync(const AuthInput& input) const {
  // The input must contain user input, otherwise there's nothing to verify.
  if (!input.user_input) {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocScryptVerifierVerifyNoUserInput),
        ErrorActionSet(PrimaryAction::kIncorrectAuth),
        user_data_auth::CRYPTOHOME_ERROR_INVALID_ARGUMENT);
  }
  // Scrypt the input using the verifier salt.
  brillo::SecureBlob hashed_secret(kScryptOutputSize, 0);
  if (!Scrypt(*input.user_input, scrypt_salt_, kScryptNFactor, kScryptRFactor,
              kScryptPFactor, &hashed_secret)) {
    LOG(ERROR) << "Scrypt failed.";
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocScryptVerifierVerifyScryptFailed),
        ErrorActionSet(PrimaryAction::kIncorrectAuth),
        user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
  }
  // Compare the encrypted input against the hashed secret.
  if (verifier_.size() != hashed_secret.size()) {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocScryptVerifierVerifyWrongScryptOutputSize),
        ErrorActionSet(PrimaryAction::kIncorrectAuth),
        user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
  }
  if (brillo::SecureMemcmp(hashed_secret.data(), verifier_.data(),
                           verifier_.size()) == 0) {
    return OkStatus<CryptohomeError>();
  } else {
    return MakeStatus<CryptohomeError>(
        CRYPTOHOME_ERR_LOC(kLocScryptVerifierVerifySecretMismatch),
        ErrorActionSet(PrimaryAction::kIncorrectAuth),
        user_data_auth::CRYPTOHOME_ERROR_AUTHORIZATION_KEY_FAILED);
  }
}

}  // namespace cryptohome
