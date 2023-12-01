// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Contains the implementation of class Crypto

#include "cryptohome/crypto.h"

#include <sys/types.h>
#include <unistd.h>

#include <limits>
#include <map>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>
#include <crypto/sha2.h>
#include <libhwsec/status.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/crypto/hmac.h>
#include <libhwsec-foundation/crypto/libscrypt_compat.h>
#include <libhwsec-foundation/crypto/scrypt.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "cryptohome/cryptohome_common.h"
#include "cryptohome/cryptohome_keys_manager.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/key_objects.h"
#include "cryptohome/le_credential_manager_impl.h"
#include "cryptohome/vault_keyset.h"

using base::FilePath;
using brillo::SecureBlob;
using hwsec::TPMErrorBase;
using hwsec_foundation::HmacSha256;
using hwsec_foundation::SecureBlobToHex;
using hwsec_foundation::SecureBlobToHexToBuffer;

namespace cryptohome {

namespace {

// Location where we store the Low Entropy (LE) credential manager related
// state.
const char kSignInHashTreeDir[] = "/home/.shadow/low_entropy_creds";

}  // namespace

Crypto::Crypto(const hwsec::CryptohomeFrontend* hwsec,
               const hwsec::PinWeaverFrontend* pinweaver,
               CryptohomeKeysManager* cryptohome_keys_manager,
               const hwsec::RecoveryCryptoFrontend* recovery_hwsec)
    : hwsec_(hwsec),
      pinweaver_(pinweaver),
      cryptohome_keys_manager_(cryptohome_keys_manager),
      recovery_hwsec_(recovery_hwsec) {
  CHECK(hwsec);
  CHECK(pinweaver);
  CHECK(cryptohome_keys_manager);
  // recovery_hwsec_ may be nullptr.
}

Crypto::~Crypto() {}

void Crypto::Init() {
  cryptohome_keys_manager_->Init();
  if (!le_manager_) {
    hwsec::StatusOr<bool> is_enabled = pinweaver_->IsEnabled();
    if (!is_enabled.ok()) {
      LOG(ERROR) << "Failed to get pinweaver status: " << is_enabled.status();
      // We don't report the error to the caller: this failure shouldn't abort
      // the daemon initialization.
      return;
    }

    if (is_enabled.value()) {
      le_manager_ = std::make_unique<LECredentialManagerImpl>(
          pinweaver_, base::FilePath(kSignInHashTreeDir));
    }
  }
}

void Crypto::PasswordToPasskey(const char* password,
                               const brillo::SecureBlob& salt,
                               SecureBlob* passkey) {
  CHECK(password);

  std::string ascii_salt = SecureBlobToHex(salt);
  // Convert a raw password to a password hash
  SHA256_CTX sha_context;
  SecureBlob md_value(SHA256_DIGEST_LENGTH);

  SHA256_Init(&sha_context);
  SHA256_Update(&sha_context, ascii_salt.data(), ascii_salt.length());
  SHA256_Update(&sha_context, password, strlen(password));
  SHA256_Final(md_value.data(), &sha_context);

  md_value.resize(SHA256_DIGEST_LENGTH / 2);
  SecureBlob local_passkey(SHA256_DIGEST_LENGTH);
  SecureBlobToHexToBuffer(md_value, local_passkey.data(), local_passkey.size());
  passkey->swap(local_passkey);
}

bool Crypto::ResetLeCredential(const uint64_t le_label,
                               const SecureBlob& reset_secret,
                               CryptoError& out_error) const {
  // Bail immediately if we don't have a valid LECredentialManager.
  if (!le_manager_) {
    LOG(ERROR) << "Attempting to Reset LECredential on a platform that doesn't "
                  "support LECredential";
    PopulateError(&out_error, CryptoError::CE_LE_NOT_SUPPORTED);
    return false;
  }

  LECredStatus ret = le_manager_->ResetCredential(le_label, reset_secret,
                                                  /*strong_reset=*/false);
  if (!ret.ok()) {
    PopulateError(&out_error, ret->local_lecred_error() ==
                                      LE_CRED_ERROR_INVALID_RESET_SECRET
                                  ? CryptoError::CE_LE_INVALID_SECRET
                                  : CryptoError::CE_OTHER_FATAL);
    return false;
  }
  return true;
}

int Crypto::GetWrongAuthAttempts(uint64_t le_label) const {
  DCHECK(le_manager_)
      << "le_manage_ doesn't exist when calling GetWrongAuthAttempts()";
  return le_manager_->GetWrongAuthAttempts(le_label);
}

bool Crypto::RemoveLECredential(uint64_t label) const {
  // Bail immediately if we don't have a valid LECredentialManager.
  if (!le_manager_) {
    LOG(ERROR) << "No LECredentialManager instance for RemoveLECredential.";
    return false;
  }

  return le_manager_->RemoveCredential(label).ok();
}

bool Crypto::is_cryptohome_key_loaded() const {
  return cryptohome_keys_manager_->HasAnyCryptohomeKey();
}

bool Crypto::CanUnsealWithUserAuth() const {
  hwsec::StatusOr<bool> is_ready = hwsec_->IsSealingSupported();
  if (!is_ready.ok()) {
    LOG(ERROR) << "Failed to get da mitigation status: " << is_ready.status();
    return false;
  }

  return is_ready.value();
}

}  // namespace cryptohome
