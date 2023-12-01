// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// MountHelper objects carry out mount(2) and unmount(2) operations for a single
// cryptohome mount.

#ifndef CRYPTOHOME_STORAGE_MOUNT_HELPER_H_
#define CRYPTOHOME_STORAGE_MOUNT_HELPER_H_

#include <sys/types.h>

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <brillo/process/process.h>
#include <brillo/secure_blob.h>
#include <chromeos/dbus/service_constants.h>

#include "cryptohome/platform.h"
#include "cryptohome/storage/cryptohome_vault.h"
#include "cryptohome/storage/error.h"
#include "cryptohome/storage/mount_stack.h"
#include "cryptohome/username.h"

using base::FilePath;

namespace cryptohome {

extern const char kDefaultHomeDir[];
extern const char kEphemeralCryptohomeRootContext[];
extern const char kBindMountMigrationXattrName[];
extern const char kBindMountMigratingStage[];
extern const char kBindMountMigratedStage[];

// Objects that implement MountHelperInterface can perform mount operations.
// This interface will be used as we transition all cryptohome mounts to be
// performed out-of-process.
class MountHelperInterface {
 public:
  virtual ~MountHelperInterface() {}

  // Ephemeral mounts cannot be performed twice, so cryptohome needs to be able
  // to check whether an ephemeral mount can be performed.
  virtual bool CanPerformEphemeralMount() const = 0;

  // Returns whether an ephemeral mount has been performed.
  virtual bool MountPerformed() const = 0;

  // Returns whether |path| is currently mounted as part of the ephemeral mount.
  virtual bool IsPathMounted(const base::FilePath& path) const = 0;

  // Carries out an ephemeral mount for user |username|.
  virtual StorageStatus PerformEphemeralMount(
      const Username& username,
      const base::FilePath& ephemeral_loop_device) = 0;

  // Unmounts the mount point.
  virtual void UnmountAll() = 0;

  // Carries out mount operations for a regular cryptohome.
  virtual StorageStatus PerformMount(MountType mount_type,
                                     const Username& username,
                                     const std::string& fek_signature,
                                     const std::string& fnek_signature) = 0;
};

class MountHelper : public MountHelperInterface {
 public:
  MountHelper(bool legacy_mount, bool bind_mount_downloads, Platform* platform);
  MountHelper(const MountHelper&) = delete;
  MountHelper& operator=(const MountHelper&) = delete;

  ~MountHelper() = default;

  // Returns the temporary user path while we're migrating for
  // http://crbug.com/224291.
  static base::FilePath GetNewUserPath(const Username& username);

  // Ensures that root and user mountpoints for the specified user are present.
  // Returns false if the mountpoints were not present and could not be created.
  bool EnsureUserMountPoints(const Username& username) const;

  // Mounts the tracked subdirectories from a separate cache directory. This
  // is used by LVM dm-crypt cryptohomes to separate the cache directory.
  //
  // Parameters
  //   obfuscated_username - The obfuscated form of the username
  bool MountCacheSubdirectories(const ObfuscatedUsername& obfuscated_username,
                                const base::FilePath& data_directory);

  // Sets up the ecryptfs mount.
  bool SetUpEcryptfsMount(const ObfuscatedUsername& obfuscated_username,
                          const std::string& fek_signature,
                          const std::string& fnek_signature,
                          const FilePath& mount_type);

  // Sets up the dircrypto mount.
  void SetUpDircryptoMount(const ObfuscatedUsername& obfuscated_username);

  // Sets up the dm-crypt mount.
  bool SetUpDmcryptMount(const ObfuscatedUsername& obfuscated_username,
                         const base::FilePath& data_mount_point);

  // Carries out eCryptfs/dircrypto mount(2) operations for a regular
  // cryptohome.
  StorageStatus PerformMount(MountType mount_type,
                             const Username& username,
                             const std::string& fek_signature,
                             const std::string& fnek_signature) override;

  // Carries out dircrypto mount(2) operations for an ephemeral cryptohome.
  // Does not clean up on failure.
  StorageStatus PerformEphemeralMount(
      const Username& username,
      const base::FilePath& ephemeral_loop_device) override;

  // Unmounts all mount points.
  // Relies on ForceUnmount() internally; see the caveat listed for it.
  void UnmountAll() override;

  // Returns whether an ephemeral mount operation can be performed.
  bool CanPerformEphemeralMount() const override;

  // Returns whether a mount operation has been performed.
  bool MountPerformed() const override;

  // Returns whether |path| is the destination of an existing mount.
  bool IsPathMounted(const base::FilePath& path) const override;

  // Returns a list of paths that have been mounted as part of the mount.
  std::vector<base::FilePath> MountedPaths() const;

 private:
  // Returns the mounted userhome path (e.g. /home/.shadow/.../mount/user)
  //
  // Parameters
  //   obfuscated_username - Obfuscated username field of the credentials.
  FilePath GetMountedUserHomePath(
      const ObfuscatedUsername& obfuscated_username) const;

  // Returns the mounted roothome path (e.g. /home/.shadow/.../mount/root)
  //
  // Parameters
  //   obfuscated_username - Obfuscated username field of the credentials.
  FilePath GetMountedRootHomePath(
      const ObfuscatedUsername& obfuscated_username) const;

  // Mounts a mount point and pushes it to the mount stack.
  // Returns true if the mount succeeds, false otherwise.
  //
  // Parameters
  //   src - Path to mount from
  //   dest - Path to mount to
  //   type - Filesystem type to mount with
  //   options - Filesystem options to supply
  bool MountAndPush(const base::FilePath& src,
                    const base::FilePath& dest,
                    const std::string& type,
                    const std::string& options);

  // Binds a mount point, remembering it for later unmounting.
  // Returns true if the bind succeeds, false otherwise.
  //
  // Parameters
  //   src - Path to bind from
  //   dest - Path to bind to
  //   is_shared - bind mount as MS_SHARED
  bool BindAndPush(const FilePath& src,
                   const FilePath& dest,
                   RemountOption remount = RemountOption::kNoRemount);

  // If |bind_mount_downloads_| flag is set, bind mounts |user_home|/Downloads
  // to |user_home|/MyFiles/Downloads so Files app can manage MyFiles as user
  // volume instead of just Downloads. If the flag is not set, calls
  // `MoveDownloadsToMyFiles` to migrate the user's Downloads from
  // |user_home|/Downloads to |user_home|/MyFiles/Downloads.
  bool HandleMyFilesDownloads(const base::FilePath& user_home);

  // Attempts a migration of user's Download directory from
  // |user_home|/Downloads to |user_home|/MyFiles/Downloads. Returns true if the
  // migration is considered a success or has already occurred and false in all
  // other scenarios.
  bool MoveDownloadsToMyFiles(const base::FilePath& user_home);

  // Copies the skeleton directory to the user's cryptohome.
  void CopySkeleton(const FilePath& destination) const;

  // Ensures that a specified directory exists, with all path components owned
  // by kRootUid:kRootGid.
  //
  // Parameters
  //   dir - Directory to check
  bool EnsureMountPointPath(const base::FilePath& dir) const;

  // Ensures that the |num|th component of |path| is owned by |uid|:|gid| and is
  // a directory.
  bool EnsurePathComponent(const FilePath& path, uid_t uid, gid_t gid) const;

  // Attempts to unmount a mountpoint. If the unmount fails, logs processes with
  // open handles to it and performs a lazy unmount.
  //
  // Parameters
  //   src - Path mounted at |dest|
  //   dest - Mount point to unmount
  void ForceUnmount(const base::FilePath& src, const base::FilePath& dest);

  // Facilitates migration of files from one directory to another, removing the
  // duplicates. Returns the number of items migrated that are direct children
  // of |dst| to |src|.
  int MigrateDirectory(const base::FilePath& dst,
                       const base::FilePath& src) const;

  // Bind-mounts
  //   /home/.shadow/$hash/mount/root/$daemon (*)
  // to
  //   /run/daemon-store/$daemon/$hash
  // for a hardcoded list of $daemon directories.
  //
  // This can be used to make the Cryptohome mount propagate into the daemon's
  // mount namespace. See
  // https://chromium.googlesource.com/chromiumos/docs/+/HEAD/sandboxing.md#securely-mounting-cryptohome-daemon-store-folders
  // for details.
  //
  // (*) Path for a regular mount. The path is different for an ephemeral mount.
  bool MountDaemonStoreDirectories(
      const FilePath& root_home, const ObfuscatedUsername& obfuscated_username);

  // Sets up bind mounts from |user_home| and |root_home| to
  //   - /home/chronos/user (see MountLegacyHome()),
  //   - /home/chronos/u-<user_hash>,
  //   - /home/user/<user_hash>,
  //   - /home/root/<user_hash> and
  //   - /run/daemon-store/$daemon/<user_hash>
  //     (see MountDaemonStoreDirectories()).
  // The parameters have the same meaning as in MountCryptohome resp.
  // MountEphemeralCryptohomeInner. Returns true if successful, false otherwise.
  bool MountHomesAndDaemonStores(const Username& username,
                                 const ObfuscatedUsername& obfuscated_username,
                                 const FilePath& user_home,
                                 const FilePath& root_home);

  // Mounts the legacy home directory.
  // The legacy home directory is from before multiprofile and is mounted at
  // /home/chronos/user.
  bool MountLegacyHome(const FilePath& from);

  // Recursively copies directory contents to the destination if the destination
  // file does not exist.  Sets ownership to |default_user_|.
  //
  // Parameters
  //   source - Where to copy files from
  //   destination - Where to copy files to
  void RecursiveCopy(const FilePath& source, const FilePath& destination) const;

  // Returns true if we think there was at least one successful mount in
  // the past.
  bool IsFirstMountComplete(
      const ObfuscatedUsername& obfuscated_username) const;

  bool legacy_mount_ = true;
  bool bind_mount_downloads_ = true;

  // Stack of mounts (in the mount(2) sense) that have been made.
  MountStack stack_;

  Platform* platform_;  // Un-owned.

  FRIEND_TEST(PersistentSystemTest, MountOrdering);
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_MOUNT_HELPER_H_
