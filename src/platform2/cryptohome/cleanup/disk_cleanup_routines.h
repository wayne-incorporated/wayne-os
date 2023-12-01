// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// DiskCleanupRoutines contains methods used to free up disk space.
// Used by DiskCleanup to perform the actual cleanup.

#ifndef CRYPTOHOME_CLEANUP_DISK_CLEANUP_ROUTINES_H_
#define CRYPTOHOME_CLEANUP_DISK_CLEANUP_ROUTINES_H_

#include <string>

#include <base/files/file_path.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/username.h"

namespace cryptohome {

class DiskCleanupRoutines {
 public:
  DiskCleanupRoutines(HomeDirs* homedirs, Platform* platform);
  virtual ~DiskCleanupRoutines();

  // Remove the users Cache directory.
  virtual bool DeleteUserCache(const ObfuscatedUsername& obfuscated);
  // Clear the users GDrive cache.
  virtual bool DeleteUserGCache(const ObfuscatedUsername& obfuscated);
  // Remove Dmcrypt cache.
  virtual bool DeleteCacheVault(const ObfuscatedUsername& obfuscated);
  // Remove the users Android cache.
  virtual bool DeleteUserAndroidCache(const ObfuscatedUsername& obfuscated);
  // Remove the entire user profile.
  virtual bool DeleteUserProfile(const ObfuscatedUsername& obfuscated);

 private:
  base::FilePath GetShadowDir(const ObfuscatedUsername& obfuscated) const;

  // Returns the path of the specified tracked directory (i.e. a directory which
  // we can locate even when without the key).
  bool GetTrackedDirectory(const base::FilePath& user_dir,
                           const base::FilePath& tracked_dir_name,
                           base::FilePath* out);
  // GetTrackedDirectory() implementation for dircrypto.
  bool GetTrackedDirectoryForDirCrypto(const base::FilePath& mount_dir,
                                       const base::FilePath& tracked_dir_name,
                                       base::FilePath* out);

  // Recursively deletes all contents of a directory while leaving the directory
  // itself intact.
  bool DeleteDirectoryContents(const base::FilePath& dir);

  // Recursively deletes all files that have the removable extended attribute
  // or has the no dump attribute.
  bool RemoveAllRemovableFiles(const base::FilePath& dir);

  // Not owned. Must outlive DiskCleanupRoutines.
  HomeDirs* homedirs_;
  Platform* platform_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CLEANUP_DISK_CLEANUP_ROUTINES_H_
