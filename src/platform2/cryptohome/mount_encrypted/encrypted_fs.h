// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOUNT_ENCRYPTED_ENCRYPTED_FS_H_
#define CRYPTOHOME_MOUNT_ENCRYPTED_ENCRYPTED_FS_H_

#include <inttypes.h>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/blkdev_utils/device_mapper.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/secure_blob.h>

#include "cryptohome/mount_encrypted/mount_encrypted.h"
#include "cryptohome/platform.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/encrypted_container_factory.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"

#define STATEFUL_MNT "mnt/stateful_partition"
#define ENCRYPTED_MNT STATEFUL_MNT "/encrypted"

namespace mount_encrypted {

// Teardown stage: for granular teardowns
enum class TeardownStage {
  kTeardownUnbind,
  kTeardownContainer,
};

// BindMount represents a bind mount to be setup from
// source directories within the encrypted mount.
// EncryptedFs is responsible for setting up the bind mount
// once it sets up the encrypted mount.
struct BindMount {
  base::FilePath src;  // Location of bind source.
  base::FilePath dst;  // Destination of bind.
  uid_t owner;
  gid_t group;
  mode_t mode;
  bool submount;  // Submount is bound already.
};

// EncryptedFs sets up, tears down and cleans up encrypted
// stateful mounts. Given a root directory, the class
// sets up an encrypted mount at <root_dir>/ENCRYPTED_MOUNT.
class EncryptedFs {
 public:
  // Set up the encrypted filesystem..
  EncryptedFs(const base::FilePath& rootdir,
              uint64_t fs_size,
              const std::string& dmcrypt_name,
              std::unique_ptr<cryptohome::EncryptedContainer> container,
              cryptohome::Platform* platform,
              brillo::DeviceMapper* device_mapper);
  ~EncryptedFs() = default;

  static std::unique_ptr<EncryptedFs> Generate(
      const base::FilePath& rootdir,
      cryptohome::Platform* platform,
      brillo::DeviceMapper* device_mapper,
      brillo::LogicalVolumeManager* lvm,
      cryptohome::EncryptedContainerFactory* encrypted_container_factory);

  // Setup mounts the encrypted mount by:
  // 1. Create a sparse file at <rootdir>/STATEFUL_MNT/encrypted.block
  // 2. Mounting a loop device on top of the sparse file.
  // 3. Mounting a dmcrypt device with the loop device as the backing
  //    device and the provided encryption key.
  // 4. Formatting the dmcrypt device as ext4 and mounting it at the
  //    mount_point.
  // If a sparse file already exists, Setup assumes that the stateful
  // mount has already been setup and attempts to mount the
  // | ext4 | dmcrypt | loopback | tower on top of the sparse file.
  // Parameters
  //   encryption_key - dmcrypt encryption key.
  //   rebuild - cleanup and recreate the encrypted mount.
  result_code Setup(const cryptohome::FileSystemKey& encryption_key,
                    bool rebuild);
  // Purge - obliterate the sparse file. This should be called only
  // when the encrypted fs is not mounted.
  bool Purge(void);
  // Teardown - stepwise unmounts the | ext4 | dmcrypt | loopback | tower
  // on top of the sparse file.
  result_code Teardown(void);
  // CheckStates - Checks validity for the stateful mount before mounting.
  result_code CheckStates(void);
  // ReportInfo - Reports the paths and bind mounts.
  result_code ReportInfo(void) const;

 private:
  friend class EncryptedFsTest;
  FRIEND_TEST(EncryptedFsTest, RebuildStateful);
  FRIEND_TEST(EncryptedFsTest, OldStateful);
  FRIEND_TEST(EncryptedFsTest, LoopdevTeardown);
  FRIEND_TEST(EncryptedFsTest, DevmapperTeardown);

  // TeardownByStage allows higher granularity over teardown
  // processes.
  result_code TeardownByStage(TeardownStage stage, bool ignore_errors);

  // Root directory to use for the encrypted stateful filesystem.
  const base::FilePath rootdir_;
  // Size of the filesystem.
  const uint64_t fs_size_;

  // Dm-crypt device name: used for key finalization.
  const std::string dmcrypt_name_;

  // File paths used by encrypted stateful.
  const base::FilePath stateful_mount_;
  const base::FilePath block_path_;
  const base::FilePath dmcrypt_dev_;
  const base::FilePath encrypted_mount_;

  // Use a raw Platform pointer to avoid convoluted EXPECT_CALL semantics
  // for mock Platform objects.
  cryptohome::Platform* platform_;
  // Device Mapper.
  brillo::DeviceMapper* device_mapper_;

  // Encrypted container that will be mounted as the encrypted filesystem.
  std::unique_ptr<cryptohome::EncryptedContainer> container_;

  std::vector<BindMount> bind_mounts_;
};

}  // namespace mount_encrypted

#endif  // CRYPTOHOME_MOUNT_ENCRYPTED_ENCRYPTED_FS_H_
