// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USER_SESSION_USER_SESSION_H_
#define CRYPTOHOME_USER_SESSION_USER_SESSION_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/timer/timer.h>
#include <brillo/secure_blob.h>

#include "cryptohome/credential_verifier.h"
#include "cryptohome/error/cryptohome_mount_error.h"
#include "cryptohome/migration_type.h"
#include "cryptohome/pkcs11/pkcs11_token.h"
#include "cryptohome/storage/cryptohome_vault.h"
#include "cryptohome/storage/mount.h"
#include "cryptohome/username.h"

namespace cryptohome {

class UserSession {
 public:
  UserSession() = default;
  virtual ~UserSession() = default;

  // Disallow Copy/Move/Assign
  UserSession(const UserSession&) = delete;
  UserSession(const UserSession&&) = delete;
  void operator=(const UserSession&) = delete;
  void operator=(const UserSession&&) = delete;

  // Returns whether the user session represents an active login session.
  virtual bool IsActive() const = 0;

  // Returns whether the session is for an ephemeral user.
  virtual bool IsEphemeral() const = 0;

  // Returns whether the path belong to the session.
  // TODO(dlunev): remove it once recovery logic is embedded into storage code.
  virtual bool OwnsMountPoint(const base::FilePath& path) const = 0;

  // Perform migration of the vault to a different encryption type.
  virtual bool MigrateVault(const Mount::MigrationCallback& callback,
                            MigrationType migration_type) = 0;

  // Mounts disk backed vault for the given username with the supplied file
  // system keyset.
  virtual MountStatus MountVault(
      const Username& username,
      const FileSystemKeyset& fs_keyset,
      const CryptohomeVault::Options& vault_options) = 0;

  // Creates and mounts a ramdisk backed ephemeral session for the given user.
  virtual MountStatus MountEphemeral(const Username& username) = 0;

  // Creates and mounts a ramdisk backed ephemeral session for an anonymous
  // user.
  virtual MountStatus MountGuest() = 0;

  // Unmounts the session.
  virtual bool Unmount() = 0;

  // Returns the WebAuthn secret and clears it from memory.
  virtual std::unique_ptr<brillo::SecureBlob> GetWebAuthnSecret() = 0;

  // Returns the WebAuthn secret hash.
  virtual const brillo::SecureBlob& GetWebAuthnSecretHash() const = 0;

  // Returns the hibernate secret.
  virtual std::unique_ptr<brillo::SecureBlob> GetHibernateSecret() = 0;

  // Checks that the session belongs to the obfuscated_user.
  virtual bool VerifyUser(
      const ObfuscatedUsername& obfuscated_username) const = 0;

  // Returns PKCS11 token associated with the session.
  virtual Pkcs11Token* GetPkcs11Token() = 0;

  // Returns the name of the user associated with the session.
  virtual Username GetUsername() const = 0;

  // Computes a public derivative from |fek| and |fnek| for u2fd to fetch.
  virtual void PrepareWebAuthnSecret(const brillo::SecureBlob& fek,
                                     const brillo::SecureBlob& fnek) = 0;

  // Resets the application container for a given session.
  virtual bool ResetApplicationContainer(const std::string& application) = 0;

  // =============== Credential storage functions ===============
  // These functions are used to read and write credential state stored in the
  // user session. They are implemented directly as non-virtual functions
  // because it doesn't make sense to implement them differently, even in tests.

  // Credential Verifiers (labeled vs labelless)
  // UserSessions can have any number of verifiers associated with them.
  // Normally, most verifiers are identified by a label and in those cases they
  // will be stored in label->verifier map. However, there are some special
  // types of verifiers which do not support labels, and in those cases the
  // labels will instead be stored by type, in a separate type->verifier map.
  //
  // To support this, most of the lookup functions provide both label and type
  // overloads, the former for looking up labelled verifiers and the latter for
  // looking up labelless ones. Note that the lookup-by-type functions will
  // never returned labelled verifiers.

  // Adds a new credential verifier to this session. Verifiers with a label are
  // stored by label, and verifiers without a label are stored by type. New
  // verifiers will replace old ones if they have a matching identifier.
  void AddCredentialVerifier(std::unique_ptr<CredentialVerifier> verifier);

  // Returns a bool indicating if this session has any credential verifiers
  // (0-arg) or if it has a verifier with a specific label or type (1-arg).
  bool HasCredentialVerifier() const;
  bool HasCredentialVerifier(const std::string& label) const;
  bool HasCredentialVerifier(AuthFactorType type) const;

  // Returns the credential verifier for the given label, or the labelless
  // verifier for the given type if one exists. Otherwise returns null.
  const CredentialVerifier* FindCredentialVerifier(
      const std::string& label) const;
  const CredentialVerifier* FindCredentialVerifier(AuthFactorType type) const;

  // Returns all the credential verifiers for this session.
  std::vector<const CredentialVerifier*> GetCredentialVerifiers() const;

  // Removes the credential_verifier with the given label or type, and possibly
  // the key data as well if it has the same label.
  void RemoveCredentialVerifier(const std::string& key_label);
  void RemoveCredentialVerifier(AuthFactorType type);

 private:
  // Storage for CredentialVerifiers associated with the session.
  std::map<std::string, std::unique_ptr<CredentialVerifier>>
      label_to_credential_verifier_;
  std::map<AuthFactorType, std::unique_ptr<CredentialVerifier>>
      type_to_credential_verifier_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_USER_SESSION_USER_SESSION_H_
