// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Mount - class for managing cryptohome user keys and mounts.  In Chrome OS,
// users are managed on top of a shared unix user, chronos.  When a user logs
// in, cryptohome mounts their encrypted home directory to /home/chronos/user,
// and Chrome does a profile switch to that directory.  All user data in their
// home directory is transparently encrypted, providing protection against
// offline theft.  On logout, the mount point is removed.

#ifndef CRYPTOHOME_STORAGE_MOUNT_H_
#define CRYPTOHOME_STORAGE_MOUNT_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/callback.h>
#include <base/memory/ref_counted.h>
#include <base/synchronization/condition_variable.h>
#include <base/synchronization/lock.h>
#include <base/time/time.h>
#include <base/values.h>
#include <brillo/secure_blob.h>
#include <chromeos/dbus/service_constants.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gtest/gtest_prod.h>
#include <policy/device_policy.h>
#include <policy/libpolicy.h>

#include "cryptohome/data_migrator/migration_helper.h"
#include "cryptohome/migration_type.h"
#include "cryptohome/platform.h"
#include "cryptohome/storage/cryptohome_vault.h"
#include "cryptohome/storage/error.h"
#include "cryptohome/storage/file_system_keyset.h"
#include "cryptohome/storage/homedirs.h"
#include "cryptohome/storage/mount_constants.h"
#include "cryptohome/storage/mount_helper.h"
#include "cryptohome/storage/out_of_process_mount_helper.h"
#include "cryptohome/username.h"
#include "cryptohome/vault_keyset.h"
#include "cryptohome/vault_keyset.pb.h"

namespace cryptohome {

// The Mount class handles mounting/unmounting of the user's cryptohome
// directory.
class Mount : public base::RefCountedThreadSafe<Mount> {
 public:
  // Called before mount cryptohome.
  using PreMountCallback = base::RepeatingCallback<void()>;

  // Called during and at the end of the Ext4 migration to report the progress.
  using MigrationCallback = base::RepeatingCallback<void(
      const user_data_auth::DircryptoMigrationProgress&)>;

  // Sets up Mount with the default locations, username, etc., as defined above.
  Mount();
  Mount(Platform* platform,
        HomeDirs* homedirs,
        bool legacy_mount = true,
        bool bind_mount_downloads = true,
        bool use_local_mounter = false);
  Mount(const Mount&) = delete;
  Mount& operator=(const Mount&) = delete;

  virtual ~Mount();

  // Attempts to mount the cryptohome for the given username
  //
  // Parameters
  //   username - name of the user to mount
  //   file_system_keys - file system encryption keys of the user
  //   mount_args - The options for the call to mount:
  //                * Whether to create the cryptohome if it doesn't exist.
  //                * Whether to ensure that the mount is ephemeral.
  //   error - The specific error condition on failure
  virtual StorageStatus MountCryptohome(
      const Username& username,
      const FileSystemKeyset& file_system_keys,
      const CryptohomeVault::Options& vault_options);

  // Attempts to mount an ephemeral cryptohome for the given username.
  //
  // Parameters
  //   username - name of the user to mount
  virtual StorageStatus MountEphemeralCryptohome(const Username& username);

  // Unmounts any mount at the cryptohome mount point
  virtual bool UnmountCryptohome();

  // Checks whether the mount point currently has a cryptohome mounted for the
  // current user.
  virtual bool IsMounted() const;

  // Returns true if the mount is ephemeral;
  virtual bool IsEphemeral() const;

  // Checks whether the mount point currently has a cryptohome mounted for the
  // current user that is not ephemeral.
  //
  virtual bool IsNonEphemeralMounted() const;

  // Get the HomeDirs instance
  virtual HomeDirs* homedirs() { return homedirs_; }

  // Returns associated platform object
  virtual Platform* platform() { return platform_; }

  // Return the the mount type as a string.
  virtual std::string GetMountTypeString() const;

  // Returns true if this Mount instances owns the mount path.
  virtual bool OwnsMountPoint(const base::FilePath& path) const;

  // Migrates the vault's encryption type.
  // Call MountCryptohome with to_migrate_from_ecryptfs beforehand.
  // If |migration_type| is MINIMAL, no progress reporting will be done and only
  // allowlisted paths will be migrated.
  virtual bool MigrateEncryption(const MigrationCallback& callback,
                                 MigrationType migration_type);

  // Cancels the active encryption migration if there is, and wait for it to
  // stop.
  void MaybeCancelMigrateEncryptionAndWait();

  // Reset application container.
  bool ResetApplicationContainer(const std::string& application);

 private:
  // Gets the directory to mount the user's ephemeral cryptohome at.
  //
  // Parameters
  //   obfuscated_username - Obfuscated username field of the credentials.
  base::FilePath GetUserEphemeralMountDirectory(
      const std::string& obfuscated_username) const;

  // Returns the path of a user passthrough inside a vault
  //
  // Parameters
  //   vault - vault path
  base::FilePath VaultPathToUserPath(const base::FilePath& vault) const;

  // Returns the path of a root passthrough inside a vault
  //
  // Parameters
  //   vault - vault path
  base::FilePath VaultPathToRootPath(const base::FilePath& vault) const;

  // Returns the mounted userhome path for ephemeral user
  // (e.g. /home/.shadow/.../ephemeral-mount/user)
  //
  // Parameters
  //   obfuscated_username - Obfuscated username field of the credentials.
  base::FilePath GetMountedEphemeralUserHomePath(
      const std::string& obfuscated_username) const;

  // Returns the mounted roothome path for ephemeral user (
  // e.g. /home/.shadow/.../ephemeral-mount/root)
  //
  // Parameters
  //   obfuscated_username - Obfuscated username field of the credentials.
  base::FilePath GetMountedEphemeralRootHomePath(
      const std::string& obfuscated_username) const;

  bool MigrateFromEcryptfs(
      const data_migrator::MigrationHelper::ProgressCallback& callback,
      MigrationType migration_type);

  bool MigrateFromDircrypto(
      const data_migrator::MigrationHelper::ProgressCallback& callback,
      MigrationType migration_type);

  bool PerformMigration(
      const data_migrator::MigrationHelper::ProgressCallback& callback,
      const base::FilePath& source,
      const base::FilePath& destination,
      const base::FilePath& status_files_dir,
      MigrationType migration_type);

  // A special of UnmountCryptohome to be called from the migration path.
  void UnmountCryptohomeFromMigration();

  // Return the the mount type as a string.
  MountType GetMountType() const;

  // The uid of the shared user.  Ownership of the user's vault is set to this
  // uid.
  uid_t default_user_;

  // The gid of the shared user.  Ownership of the user's vault is set to this
  // gid.
  gid_t default_group_;

  // The gid of the shared access group.  Ownership of the user's home and
  // Downloads directory to this gid.
  gid_t default_access_group_;

  // The file path to mount cryptohome at.  Defaults to /home/chronos/user
  base::FilePath mount_point_;

  // The platform-specific calls
  Platform* platform_;

  // HomeDirs encapsulates operations on Cryptohomes at rest.
  HomeDirs* homedirs_;

  // Name of the user the mount belongs to.
  Username username_;

  // Whether to mount the legacy homedir or not (see MountLegacyHome)
  bool legacy_mount_;

  // Whether to bind mount Downloads/.
  bool bind_mount_downloads_;

  data_migrator::MigrationHelper* active_dircrypto_migrator_ = nullptr;
  bool is_dircrypto_migration_cancelled_ = false;
  base::Lock active_dircrypto_migrator_lock_;
  base::ConditionVariable dircrypto_migration_stopped_condition_;

  std::unique_ptr<MountHelperInterface> active_mounter_;

  // Represents the user's cryptohome vault.
  std::unique_ptr<CryptohomeVault> user_cryptohome_vault_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_STORAGE_MOUNT_H_
