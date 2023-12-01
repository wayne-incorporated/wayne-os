// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_MOCK_HOMEDIRS_H_
#define CRYPTOHOME_STORAGE_MOCK_HOMEDIRS_H_

#include "cryptohome/storage/homedirs.h"

#include <memory>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <dbus/cryptohome/dbus-constants.h>
#include <gmock/gmock.h>

#include "cryptohome/storage/error.h"
#include "cryptohome/storage/mount.h"
#include "cryptohome/username.h"

namespace cryptohome {
class DiskCleanup;
class VaultKeyset;

class MockHomeDirs : public HomeDirs {
 public:
  MockHomeDirs() = default;
  virtual ~MockHomeDirs() = default;

  MOCK_METHOD(HomeDirs::CryptohomesRemovedStatus,
              RemoveCryptohomesBasedOnPolicy,
              (),
              (override));
  MOCK_METHOD(bool, GetOwner, (ObfuscatedUsername*), (override));
  MOCK_METHOD(bool, GetPlainOwner, (Username*), (override));
  MOCK_METHOD(bool,
              GetEphemeralSettings,
              (policy::DevicePolicy::EphemeralSettings*),
              (override));
  MOCK_METHOD(bool, KeylockerForStorageEncryptionEnabled, (), (override));
  MOCK_METHOD(bool, MustRunAutomaticCleanupOnLogin, (), (override));
  MOCK_METHOD(bool, Create, (const Username&), (override));
  MOCK_METHOD(bool, Remove, (const ObfuscatedUsername&), (override));
  MOCK_METHOD(int64_t, ComputeDiskUsage, (const Username&), (override));
  MOCK_METHOD(bool, Exists, (const ObfuscatedUsername&), (const, override));
  MOCK_METHOD(bool,
              DmcryptCacheContainerExists,
              (const ObfuscatedUsername&),
              (const, override));
  MOCK_METHOD(bool,
              RemoveDmcryptCacheContainer,
              (const ObfuscatedUsername&),
              (override));
  MOCK_METHOD(StorageStatusOr<bool>,
              CryptohomeExists,
              (const ObfuscatedUsername&),
              (const, override));
  MOCK_METHOD(int32_t, GetUnmountedAndroidDataCount, (), (override));

  MOCK_METHOD(bool,
              NeedsDircryptoMigration,
              (const ObfuscatedUsername&),
              (const, override));

  MOCK_METHOD(bool, SetLockedToSingleUser, (), (const, override));
  MOCK_METHOD(std::vector<HomeDir>, GetHomeDirs, (), (override));
  MOCK_METHOD(void, set_enterprise_owned, (bool), (override));
  MOCK_METHOD(bool, enterprise_owned, (), (const, override));
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_MOCK_HOMEDIRS_H_
