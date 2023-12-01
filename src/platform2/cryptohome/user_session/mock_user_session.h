// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_USER_SESSION_MOCK_USER_SESSION_H_
#define CRYPTOHOME_USER_SESSION_MOCK_USER_SESSION_H_

#include <memory>
#include <string>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>

#include "cryptohome/migration_type.h"
#include "cryptohome/pkcs11/pkcs11_token.h"
#include "cryptohome/storage/cryptohome_vault.h"
#include "cryptohome/storage/mount.h"
#include "cryptohome/user_session/user_session.h"

namespace cryptohome {

class MockUserSession : public UserSession {
 public:
  MockUserSession() = default;

  MOCK_METHOD(bool, IsActive, (), (const, override));
  MOCK_METHOD(bool, IsEphemeral, (), (const, override));
  MOCK_METHOD(bool, OwnsMountPoint, (const base::FilePath&), (const, override));
  MOCK_METHOD(bool,
              MigrateVault,
              (const Mount::MigrationCallback&, MigrationType),
              (override));
  MOCK_METHOD(MountStatus,
              MountVault,
              (const Username&,
               const FileSystemKeyset&,
               const CryptohomeVault::Options&),
              (override));
  MOCK_METHOD(MountStatus, MountEphemeral, (const Username&), (override));
  MOCK_METHOD(MountStatus, MountGuest, (), (override));
  MOCK_METHOD(bool, Unmount, (), (override));
  MOCK_METHOD(std::unique_ptr<brillo::SecureBlob>,
              GetWebAuthnSecret,
              (),
              (override));
  MOCK_METHOD(const brillo::SecureBlob&,
              GetWebAuthnSecretHash,
              (),
              (const, override));
  MOCK_METHOD(std::unique_ptr<brillo::SecureBlob>,
              GetHibernateSecret,
              (),
              (override));
  MOCK_METHOD(bool, VerifyUser, (const ObfuscatedUsername&), (const, override));
  MOCK_METHOD(Pkcs11Token*, GetPkcs11Token, (), (override));
  MOCK_METHOD(Username, GetUsername, (), (const, override));
  MOCK_METHOD(void,
              PrepareWebAuthnSecret,
              (const brillo::SecureBlob&, const brillo::SecureBlob&),
              (override));
  MOCK_METHOD(bool,
              ResetApplicationContainer,
              (const std::string&),
              (override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_USER_SESSION_MOCK_USER_SESSION_H_
