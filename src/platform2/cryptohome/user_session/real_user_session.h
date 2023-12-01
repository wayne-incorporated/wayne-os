// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USER_SESSION_REAL_USER_SESSION_H_
#define CRYPTOHOME_USER_SESSION_REAL_USER_SESSION_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/timer/timer.h>
#include <brillo/secure_blob.h>

#include "cryptohome/cleanup/user_oldest_activity_timestamp_manager.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/error/cryptohome_mount_error.h"
#include "cryptohome/keyset_management.h"
#include "cryptohome/pkcs11/pkcs11_token.h"
#include "cryptohome/pkcs11/pkcs11_token_factory.h"
#include "cryptohome/storage/cryptohome_vault.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/storage/mount.h"
#include "cryptohome/user_session/user_session.h"

namespace cryptohome {

class RealUserSession : public UserSession {
 public:
  RealUserSession() = default;
  RealUserSession(
      const Username& username,
      HomeDirs* homedirs,
      KeysetManagement* keyset_management,
      UserOldestActivityTimestampManager* user_activity_timestamp_manager,
      Pkcs11TokenFactory* pkcs11_token_factory,
      const scoped_refptr<Mount> mount);

  RealUserSession(const RealUserSession&) = delete;
  RealUserSession(const RealUserSession&&) = delete;
  void operator=(const RealUserSession&) = delete;
  void operator=(const RealUserSession&&) = delete;

  bool IsActive() const override { return mount_->IsMounted(); }

  bool IsEphemeral() const override { return mount_->IsEphemeral(); }

  bool OwnsMountPoint(const base::FilePath& path) const override {
    return mount_->OwnsMountPoint(path);
  }

  bool MigrateVault(const Mount::MigrationCallback& callback,
                    MigrationType migration_type) override {
    return mount_->MigrateEncryption(callback, migration_type);
  }

  MountStatus MountVault(
      const Username& username,
      const FileSystemKeyset& fs_keyset,
      const CryptohomeVault::Options& vault_options) override;

  MountStatus MountEphemeral(const Username& username) override;

  MountStatus MountGuest() override;

  bool Unmount() override;

  std::unique_ptr<brillo::SecureBlob> GetWebAuthnSecret() override;

  const brillo::SecureBlob& GetWebAuthnSecretHash() const override;

  std::unique_ptr<brillo::SecureBlob> GetHibernateSecret() override;

  bool VerifyUser(const ObfuscatedUsername& obfuscated_username) const override;

  Pkcs11Token* GetPkcs11Token() override { return pkcs11_token_.get(); }

  Username GetUsername() const override { return username_; }

  void PrepareWebAuthnSecret(const brillo::SecureBlob& fek,
                             const brillo::SecureBlob& fnek) override;

  bool ResetApplicationContainer(const std::string& application) override;

 private:
  // Computes a public derivative from |fek| and |fnek|, and store its hash for
  // u2fd to fetch.
  void PrepareWebAuthnSecretHash(const brillo::SecureBlob& fek,
                                 const brillo::SecureBlob& fnek);

  // Clears the WebAuthn secret if it's not read yet.
  void ClearWebAuthnSecret();

  // Computes a public derivative from |fek| and |fnek| for hiberman to fetch.
  void PrepareHibernateSecret(const brillo::SecureBlob& fek,
                              const brillo::SecureBlob& fnek);

  // Clears the WebAuthn secret if it's not read yet.
  void ClearHibernateSecret();

  const Username username_;
  const ObfuscatedUsername obfuscated_username_;

  HomeDirs* homedirs_;
  KeysetManagement* keyset_management_;
  UserOldestActivityTimestampManager* user_activity_timestamp_manager_;
  Pkcs11TokenFactory* pkcs11_token_factory_;

  // Secret for WebAuthn credentials.
  std::unique_ptr<brillo::SecureBlob> webauthn_secret_;
  // Hash of the WebAuthn secret.
  brillo::SecureBlob webauthn_secret_hash_;
  // Timer for clearing the WebAuthn secret.
  base::OneShotTimer clear_webauthn_secret_timer_;

  // Secret for securing hibernate images.
  std::unique_ptr<brillo::SecureBlob> hibernate_secret_;
  // Timer for clearing the hibernate secret.
  base::OneShotTimer clear_hibernate_secret_timer_;

  scoped_refptr<Mount> mount_;
  std::unique_ptr<Pkcs11Token> pkcs11_token_;

  friend class UserDataAuthTestTasked;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_USER_SESSION_REAL_USER_SESSION_H_
