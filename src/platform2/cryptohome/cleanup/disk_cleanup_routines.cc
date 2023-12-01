// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cleanup/disk_cleanup_routines.h"

#include <memory>
#include <set>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/logging.h>

#include "cryptohome/filesystem_layout.h"
#include "cryptohome/platform.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/storage/mount_constants.h"

using base::FilePath;

namespace cryptohome {

DiskCleanupRoutines::DiskCleanupRoutines(HomeDirs* homedirs, Platform* platform)
    : homedirs_(homedirs), platform_(platform) {}

DiskCleanupRoutines::~DiskCleanupRoutines() = default;

bool DiskCleanupRoutines::DeleteUserCache(
    const ObfuscatedUsername& obfuscated) {
  FilePath user_dir = GetShadowDir(obfuscated);

  FilePath cache;
  if (!GetTrackedDirectory(
          user_dir, FilePath(kUserHomeSuffix).Append(kCacheDir), &cache)) {
    LOG(ERROR) << "Failed to locate the cache directory.";
    return false;
  }

  VLOG(1) << "Deleting Cache " << cache.value();
  if (!DeleteDirectoryContents(cache)) {
    LOG(ERROR) << "Failed to remove the Cache directory";
    return false;
  }

  return true;
}

bool DiskCleanupRoutines::DeleteUserGCache(
    const ObfuscatedUsername& obfuscated) {
  FilePath user_dir = GetShadowDir(obfuscated);

  bool ret = true;

  // GCache dirs that can be completely removed on low space.
  const FilePath kRemovableGCacheDirs[] = {
      FilePath(kUserHomeSuffix)
          .Append(kGCacheDir)
          .Append(kGCacheVersion1Dir)
          .Append(kGCacheTmpDir),
  };

  for (const auto& dir : kRemovableGCacheDirs) {
    FilePath gcachetmp;
    if (!GetTrackedDirectory(user_dir, dir, &gcachetmp)) {
      LOG(ERROR) << "Failed to locate GCache temp directory " << dir.value();
      ret = false;
      continue;
    }
    VLOG(1) << "Deleting GCache " << gcachetmp.value();
    if (!DeleteDirectoryContents(gcachetmp)) {
      LOG(ERROR) << "Failed to remove the GCache directory";
      ret = false;
    }
  }

  // GCache dirs that contain files marked as removable.
  const FilePath kCleanableGCacheDirs[] = {
      FilePath(kUserHomeSuffix).Append(kGCacheDir).Append(kGCacheVersion1Dir),
      FilePath(kUserHomeSuffix).Append(kGCacheDir).Append(kGCacheVersion2Dir),
  };

  for (const auto& dir : kCleanableGCacheDirs) {
    FilePath gcache_dir;
    if (!GetTrackedDirectory(user_dir, dir, &gcache_dir)) {
      LOG(ERROR) << "Failed to locate GCache directory " << dir.value();
      ret = false;
      continue;
    }

    VLOG(1) << "Cleaning removable files in " << gcache_dir.value();

    if (!RemoveAllRemovableFiles(gcache_dir)) {
      ret = false;
    }
  }

  return ret;
}

bool DiskCleanupRoutines::DeleteCacheVault(
    const ObfuscatedUsername& obfuscated) {
  if (!homedirs_->DmcryptCacheContainerExists(obfuscated))
    return true;

  VLOG(1) << "Deleting Cache Volume for " << obfuscated;

  return homedirs_->RemoveDmcryptCacheContainer(obfuscated);
}

bool DiskCleanupRoutines::DeleteUserAndroidCache(
    const ObfuscatedUsername& obfuscated) {
  FilePath user_dir = GetShadowDir(obfuscated);

  bool ret = true;

  FilePath root;
  if (!GetTrackedDirectory(user_dir, FilePath(kRootHomeSuffix), &root)) {
    LOG(ERROR) << "Failed to locate the root directory.";
    return false;
  }
  // The package directory stores the inodes of the cache directory and code
  // cache directory in the kAndroidCacheInodeAttribute xattr and
  // kAndroidCodeCacheInodeAttribute xattr.  Data is stored under
  // root/android-data/data/data/<package name>/[code_]cache. It is not
  // desirable to make all package name directories unencrypted, they
  // are not marked as tracked directory.
  // TODO(crbug/625872): Mark root/android/data/data/ as pass through.

  // A set of parent directory/inode combinations.  We need the parent directory
  // as the inodes may have been re-used elsewhere if the cache directory was
  // deleted.
  std::set<std::pair<const FilePath, ino_t>> cache_inodes;
  std::unique_ptr<FileEnumerator> file_enumerator(platform_->GetFileEnumerator(
      root, true, base::FileEnumerator::DIRECTORIES));
  FilePath next_path;
  while (!(next_path = file_enumerator->Next()).empty()) {
    ino_t inode = file_enumerator->GetInfo().stat().st_ino;
    std::pair<const FilePath, ino_t> parent_inode_pair =
        std::make_pair(next_path.DirName(), inode);
    if (cache_inodes.find(parent_inode_pair) != cache_inodes.end()) {
      VLOG(1) << "Deleting Android Cache " << next_path.value();
      if (!DeleteDirectoryContents(next_path)) {
        LOG(ERROR) << "Failed to remove android cache " << next_path.value();
        ret = false;
      }
      cache_inodes.erase(parent_inode_pair);
    }
    for (const char* attribute :
         {kAndroidCacheInodeAttribute, kAndroidCodeCacheInodeAttribute}) {
      if (platform_->HasExtendedFileAttribute(next_path, attribute)) {
        uint64_t inode;
        if (platform_->GetExtendedFileAttribute(next_path, attribute,
                                                reinterpret_cast<char*>(&inode),
                                                sizeof(inode))) {
          // Because FileEnumerator processes all entries in a directory before
          // continuing to sub-directories we can assume that the inode is added
          // here before the directory that has the inode is processed.
          cache_inodes.insert(std::make_pair(next_path, inode));
        }
      }
    }
  }

  return ret;
}

bool DiskCleanupRoutines::DeleteUserProfile(
    const ObfuscatedUsername& obfuscated) {
  FilePath shadow_dir = GetShadowDir(obfuscated);

  if (!homedirs_->Remove(obfuscated)) {
    PLOG(WARNING) << "Failed to remove user profile";
    return false;
  }

  return true;
}

base::FilePath DiskCleanupRoutines::GetShadowDir(
    const ObfuscatedUsername& obfuscated) const {
  return ShadowRoot().Append(*obfuscated);
}

bool DiskCleanupRoutines::GetTrackedDirectory(const FilePath& user_dir,
                                              const FilePath& tracked_dir_name,
                                              FilePath* out) {
  FilePath vault_path = user_dir.Append(kEcryptfsVaultDir);
  if (platform_->DirectoryExists(vault_path)) {
    // On Ecryptfs, tracked directories' names are not encrypted.
    *out = user_dir.Append(kEcryptfsVaultDir).Append(tracked_dir_name);
    return true;
  }
  // This is dircrypto. Use the xattr to locate the directory.
  return GetTrackedDirectoryForDirCrypto(user_dir.Append(kMountDir),
                                         tracked_dir_name, out);
}

bool DiskCleanupRoutines::GetTrackedDirectoryForDirCrypto(
    const FilePath& mount_dir,
    const FilePath& tracked_dir_name,
    FilePath* out) {
  FilePath current_name;
  FilePath current_path = mount_dir;

  // Iterate over name components. This way, we don't have to inspect every
  // directory under |mount_dir|.
  std::vector<std::string> name_components = tracked_dir_name.GetComponents();
  for (const auto& name_component : name_components) {
    FilePath next_path;
    std::unique_ptr<FileEnumerator> enumerator(
        platform_->GetFileEnumerator(current_path, false /* recursive */,
                                     base::FileEnumerator::DIRECTORIES));
    for (FilePath dir = enumerator->Next(); !dir.empty();
         dir = enumerator->Next()) {
      if (platform_->HasExtendedFileAttribute(dir,
                                              kTrackedDirectoryNameAttribute)) {
        std::string name;
        if (!platform_->GetExtendedFileAttributeAsString(
                dir, kTrackedDirectoryNameAttribute, &name))
          return false;
        if (name == name_component) {
          // This is the directory we're looking for.
          next_path = dir;
          break;
        }
      }
    }
    if (next_path.empty()) {
      LOG(ERROR) << "Tracked dir not found " << tracked_dir_name.value();
      return false;
    }
    current_path = next_path;
  }
  *out = current_path;
  return true;
}

bool DiskCleanupRoutines::DeleteDirectoryContents(const FilePath& dir) {
  bool ret = true;
  std::unique_ptr<FileEnumerator> subdir_enumerator(
      platform_->GetFileEnumerator(dir, false,
                                   base::FileEnumerator::FILES |
                                       base::FileEnumerator::DIRECTORIES |
                                       base::FileEnumerator::SHOW_SYM_LINKS));
  for (FilePath subdir_path = subdir_enumerator->Next(); !subdir_path.empty();
       subdir_path = subdir_enumerator->Next()) {
    if (!platform_->DeletePathRecursively(subdir_path)) {
      PLOG(WARNING) << "Failed to remove " << subdir_path.value();
      ret = false;
    }
  }

  return ret;
}

bool DiskCleanupRoutines::RemoveAllRemovableFiles(const FilePath& dir) {
  bool ret = true;

  std::unique_ptr<FileEnumerator> file_enumerator(
      platform_->GetFileEnumerator(dir, true, base::FileEnumerator::FILES));
  for (FilePath file = file_enumerator->Next(); !file.empty();
       file = file_enumerator->Next()) {
    if (platform_->HasNoDumpFileAttribute(file) ||
        platform_->HasExtendedFileAttribute(file, kRemovableFileAttribute)) {
      if (!platform_->DeleteFile(file)) {
        PLOG(WARNING) << "Failed to remove: " << file.value();
        ret = false;
      }
    }
  }

  return ret;
}

}  // namespace cryptohome
