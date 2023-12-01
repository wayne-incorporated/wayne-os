// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_STORAGE_MOUNT_CONSTANTS_H_
#define CRYPTOHOME_STORAGE_MOUNT_CONSTANTS_H_

#include <sys/types.h>

namespace cryptohome {

enum class MountType {
  NONE,                    // Not mounted.
  ECRYPTFS,                // Encrypted with ecryptfs.
  DIR_CRYPTO,              // Encrypted with dircrypto.
  DMCRYPT,                 // Encrypted with dmcrypt over a logical volume.
  EPHEMERAL,               // Ephemeral mount.
  ECRYPTFS_TO_DIR_CRYPTO,  // Vault migration.
  ECRYPTFS_TO_DMCRYPT,     // Vault migration.
  DIR_CRYPTO_TO_DMCRYPT,   // Vault migration.
};

// Paths to sparse file for ephemeral mounts.
extern const char kEphemeralCryptohomeDir[];
extern const char kSparseFileDir[];

extern const char kDefaultSharedUser[];

// Directories that we intend to track (make pass-through in cryptohome vault)
extern const char kCacheDir[];
extern const char kDownloadsDir[];
extern const char kDownloadsBackupDir[];
extern const char kMyFilesDir[];
extern const char kGCacheDir[];

// subdir of kGCacheDir
extern const char kGCacheVersion1Dir[];
extern const char kGCacheVersion2Dir[];

// subdir of kGCacheVersion1Dir
extern const char kGCacheTmpDir[];

extern const char kGCacheBlobsDir[];

extern const char kUserHomeSuffix[];
extern const char kRootHomeSuffix[];

extern const char kUserHomeSuffix[];
extern const char kRootHomeSuffix[];

extern const char kEphemeralMountDir[];
extern const char kEphemeralMountType[];
extern const char kEphemeralMountOptions[];

// Daemon store directories.
extern const char kEtcDaemonStoreBaseDir[];
extern const char kRunDaemonStoreBaseDir[];

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_MOUNT_CONSTANTS_H_
