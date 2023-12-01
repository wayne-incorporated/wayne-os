// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Crypto - class for handling the keyset key management functions relating to
// cryptohome.

#ifndef CRYPTOHOME_CRYPTO_H_
#define CRYPTOHOME_CRYPTO_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <libhwsec/frontend/cryptohome/frontend.h>
#include <libhwsec/frontend/pinweaver/frontend.h>
#include <libhwsec/frontend/recovery_crypto/frontend.h>

#include "cryptohome/crypto_error.h"
#include "cryptohome/cryptohome_keys_manager.h"
#include "cryptohome/le_credential_manager.h"

namespace cryptohome {

class VaultKeyset;

class Crypto final {
 public:
  explicit Crypto(const hwsec::CryptohomeFrontend* hwsec,
                  const hwsec::PinWeaverFrontend* pinweaver,
                  CryptohomeKeysManager* cryptohome_keys_manager,
                  const hwsec::RecoveryCryptoFrontend* recovery_hwsec);
  Crypto(const Crypto&) = delete;
  Crypto& operator=(const Crypto&) = delete;

  ~Crypto();

  // Must be called before calling any other method (except test-only dependency
  // injectors).
  void Init();

  // Converts a null-terminated password to a passkey (ascii-encoded first half
  // of the salted SHA256 hash of the password).
  //
  // Parameters
  //   password - The password to convert
  //   salt - The salt used during hashing
  //   passkey (OUT) - The passkey
  static void PasswordToPasskey(const char* password,
                                const brillo::SecureBlob& salt,
                                brillo::SecureBlob* passkey);

  // Removes an LE credential specified by |label|.
  // Returns true on success, false otherwise.
  [[nodiscard]] bool RemoveLECredential(uint64_t label) const;

  // Resets an LE Credential specified by |le_label|.
  // Returns true on success.
  // On failure, false is returned and |error| is set with the appropriate
  // error.
  [[nodiscard]] bool ResetLeCredential(const uint64_t le_label,
                                       const brillo::SecureBlob& reset_secret,
                                       CryptoError& out_error) const;

  // Returns whether TPM unseal operations with direct authorization are allowed
  // on this device. Some devices cannot reset the dictionary attack counter.
  // And if unseal is performed with wrong authorization value, the counter
  // increases which might eventually temporary block the TPM. To avoid this
  // we don't allow the unseal with authorization. For details see
  // https://buganizer.corp.google.com/issues/127321828.
  bool CanUnsealWithUserAuth() const;

  // Returns the number of wrong authentication attempts for the LE keyset.
  int GetWrongAuthAttempts(uint64_t le_label) const;

  // Gets the HWSec implementation
  const hwsec::CryptohomeFrontend* GetHwsec() { return hwsec_; }

  // Gets the CryptohomeKeysManager object.
  CryptohomeKeysManager* cryptohome_keys_manager() {
    return cryptohome_keys_manager_;
  }

  // Gets the hwsec::RecoveryCryptoFrontend object.
  const hwsec::RecoveryCryptoFrontend* GetRecoveryCrypto() {
    return recovery_hwsec_;
  }

  // Gets an instance of the LECredentialManagerImpl object.
  LECredentialManager* le_manager() { return le_manager_.get(); }

  // Checks if the cryptohome key is loaded in TPM
  bool is_cryptohome_key_loaded() const;

  void set_le_manager_for_testing(
      std::unique_ptr<LECredentialManager> le_manager) {
    le_manager_ = std::move(le_manager);
  }

 private:
  // The HWSec implementation.
  const hwsec::CryptohomeFrontend* const hwsec_;

  // The pinweaver implementation.
  const hwsec::PinWeaverFrontend* const pinweaver_;

  // The CryptohomeKeysManager object used to reload Cryptohome keys.
  CryptohomeKeysManager* const cryptohome_keys_manager_;

  // The cryptohome recovery backend.
  const hwsec::RecoveryCryptoFrontend* const recovery_hwsec_;

  // Handler for Low Entropy credentials.
  std::unique_ptr<LECredentialManager> le_manager_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CRYPTO_H_
