// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_MOCK_MOUNT_H_
#define CRYPTOHOME_STORAGE_MOCK_MOUNT_H_

#include "cryptohome/storage/mount.h"

#include <string>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

namespace cryptohome {
class Credentials;

class MockMount : public Mount {
 public:
  MockMount() = default;
  ~MockMount() override = default;
  MOCK_METHOD(StorageStatus,
              MountCryptohome,
              (const Username&,
               const FileSystemKeyset&,
               const CryptohomeVault::Options&),
              (override));
  MOCK_METHOD(StorageStatus,
              MountEphemeralCryptohome,
              (const Username&),
              (override));
  MOCK_METHOD(bool, UnmountCryptohome, (), (override));
  MOCK_METHOD(bool, IsMounted, (), (const, override));
  MOCK_METHOD(bool, IsEphemeral, (), (const, override));
  MOCK_METHOD(bool, IsNonEphemeralMounted, (), (const, override));
  MOCK_METHOD(bool, OwnsMountPoint, (const base::FilePath&), (const, override));

  MOCK_METHOD(bool,
              MigrateEncryption,
              (const MigrationCallback&, MigrationType),
              (override));
};
}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_MOCK_MOUNT_H_
