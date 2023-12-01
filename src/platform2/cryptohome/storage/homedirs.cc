// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/homedirs.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <set>
#include <utility>
#include <vector>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <brillo/cryptohome.h>
#include <brillo/blkdev_utils/lvm.h>
#include <brillo/scoped_umask.h>
#include <brillo/secure_blob.h>
#include <chromeos/constants/cryptohome.h>
#include <cryptohome/proto_bindings/key.pb.h>
#include <libhwsec-foundation/status/status_chain_macros.h>

#include "cryptohome/crypto.h"
#include "cryptohome/crypto_error.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/dircrypto_util.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/platform.h"
#include "cryptohome/storage/cryptohome_vault.h"
#include "cryptohome/storage/cryptohome_vault_factory.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/ephemeral_policy_util.h"
#include "cryptohome/storage/error.h"
#include "cryptohome/storage/mount_helper.h"
#include "cryptohome/username.h"

using base::FilePath;
using brillo::SecureBlob;
using brillo::cryptohome::home::SanitizeUserName;

namespace cryptohome {

const char* kEmptyOwner = "";
// Each xattr is set to Android app internal data directory, contains
// 8-byte inode number of cache subdirectory.  See
// frameworks/base/core/java/android/app/ContextImpl.java
const char kAndroidCacheInodeAttribute[] = "user.inode_cache";
const char kAndroidCodeCacheInodeAttribute[] = "user.inode_code_cache";
const char kTrackedDirectoryNameAttribute[] = "user.TrackedDirectoryName";
const char kRemovableFileAttribute[] = "user.GCacheRemovable";
const char kForceKeylockerForTestingFlag[] =
    "/run/cryptohome/.force_keylocker_for_testing";

HomeDirs::HomeDirs(Platform* platform,
                   std::unique_ptr<policy::PolicyProvider> policy_provider,
                   const RemoveCallback& remove_callback,
                   CryptohomeVaultFactory* vault_factory)
    : platform_(platform),
      policy_provider_(std::move(policy_provider)),
      enterprise_owned_(false),
      lvm_migration_enabled_(false),
      vault_factory_(vault_factory),
      remove_callback_(remove_callback) {}

HomeDirs::~HomeDirs() {}

void HomeDirs::LoadDevicePolicy() {
  policy_provider_->Reload();
}

bool HomeDirs::GetEphemeralSettings(
    policy::DevicePolicy::EphemeralSettings* settings) {
  LoadDevicePolicy();
  if (!policy_provider_->device_policy_is_loaded()) {
    return false;
  }

  if (!policy_provider_->GetDevicePolicy().GetEphemeralSettings(settings)) {
    return false;
  }

  return true;
}

bool HomeDirs::KeylockerForStorageEncryptionEnabled() {
  // Search through /proc/crypto for 'aeskl' as an indicator that AES Keylocker
  // is supported.
  if (!IsAesKeylockerSupported())
    return false;

  // Check if keylocker is force enabled for testing.
  // TODO(sarthakkukreti@, b/209516710): Remove in M102.
  if (platform_->FileExists(base::FilePath(kForceKeylockerForTestingFlag))) {
    LOG(INFO) << "Forced keylocker enabled for testing";
    return true;
  }

  LoadDevicePolicy();

  // If the policy cannot be loaded, default to AESNI.
  bool keylocker_for_storage_encryption_enabled = false;
  if (policy_provider_->device_policy_is_loaded())
    policy_provider_->GetDevicePolicy()
        .GetDeviceKeylockerForStorageEncryptionEnabled(
            &keylocker_for_storage_encryption_enabled);
  return keylocker_for_storage_encryption_enabled;
}

bool HomeDirs::MustRunAutomaticCleanupOnLogin() {
  // If the policy cannot be loaded, default to not run cleanup.
  if (!policy_provider_->device_policy_is_loaded())
    return false;

  // If the device is not enterprise owned, do not run cleanup.
  if (!enterprise_owned()) {
    return false;
  }

  // Get the value of the policy and default to true if unset.
  return policy_provider_->GetDevicePolicy()
      .GetRunAutomaticCleanupOnLogin()
      .value_or(true);
}

bool HomeDirs::SetLockedToSingleUser() const {
  return platform_->TouchFileDurable(base::FilePath(kLockedToSingleUserFile));
}

bool HomeDirs::Exists(const ObfuscatedUsername& obfuscated_username) const {
  FilePath user_dir = UserPath(obfuscated_username);
  return platform_->DirectoryExists(user_dir);
}

StorageStatusOr<bool> HomeDirs::CryptohomeExists(
    const ObfuscatedUsername& obfuscated_username) const {
  ASSIGN_OR_RETURN(bool dircrypto_exists,
                   DircryptoCryptohomeExists(obfuscated_username));
  return EcryptfsCryptohomeExists(obfuscated_username) || dircrypto_exists ||
         DmcryptCryptohomeExists(obfuscated_username);
}

bool HomeDirs::EcryptfsCryptohomeExists(
    const ObfuscatedUsername& obfuscated_username) const {
  // Check for the presence of a vault directory for ecryptfs.
  return platform_->DirectoryExists(
      GetEcryptfsUserVaultPath(obfuscated_username));
}

StorageStatusOr<bool> HomeDirs::DircryptoCryptohomeExists(
    const ObfuscatedUsername& obfuscated_username) const {
  // Check for the presence of an encrypted mount directory for dircrypto.
  FilePath mount_path = GetUserMountDirectory(obfuscated_username);

  if (!platform_->DirectoryExists(mount_path)) {
    return false;
  }

  switch (platform_->GetDirCryptoKeyState(mount_path)) {
    case dircrypto::KeyState::NO_KEY:
    case dircrypto::KeyState::NOT_SUPPORTED:
      return false;
    case dircrypto::KeyState::ENCRYPTED:
      return true;
    case dircrypto::KeyState::UNKNOWN:
      return StorageStatus::Make(
          FROM_HERE,
          std::string("Directory has inconsistent Fscrypt state: ") +
              mount_path.value(),
          MOUNT_ERROR_FATAL);
  }
  return false;
}

bool HomeDirs::DmcryptContainerExists(
    const ObfuscatedUsername& obfuscated_username,
    const std::string& container_suffix) const {
  // Check for the presence of the logical volume for the user's data container.
  std::string logical_volume_container =
      LogicalVolumePrefix(obfuscated_username).append(container_suffix);

  return vault_factory_->ContainerExists(logical_volume_container);
}

bool HomeDirs::DmcryptCryptohomeExists(
    const ObfuscatedUsername& obfuscated_username) const {
  return DmcryptContainerExists(obfuscated_username,
                                kDmcryptDataContainerSuffix);
}

bool HomeDirs::DmcryptCacheContainerExists(
    const ObfuscatedUsername& obfuscated_username) const {
  return DmcryptContainerExists(obfuscated_username,
                                kDmcryptCacheContainerSuffix);
}

HomeDirs::CryptohomesRemovedStatus HomeDirs::RemoveCryptohomesBasedOnPolicy() {
  // If the device is not enterprise owned it should have an owner user.
  auto state = HomeDirs::CryptohomesRemovedStatus::kError;
  ObfuscatedUsername owner;
  bool has_owner = GetOwner(&owner);
  if (!enterprise_owned() && !has_owner) {
    return state;
  }

  auto homedirs = GetHomeDirs();
  FilterMountedHomedirs(&homedirs);
  policy::DevicePolicy::EphemeralSettings settings;
  if (!GetEphemeralSettings(&settings)) {
    return state;
  }

  size_t cryptohomes_removed = 0;
  EphemeralPolicyUtil ephemeral_util(settings);
  for (const auto& dir : homedirs) {
    if (has_owner && !enterprise_owned() && dir.obfuscated == owner) {
      continue;  // Owner vault shouldn't be remove.
    }

    if (!ephemeral_util.ShouldRemoveBasedOnPolicy(dir.obfuscated)) {
      continue;
    }

    if (HomeDirs::Remove(dir.obfuscated)) {
      cryptohomes_removed++;
    } else {
      LOG(WARNING)
          << "Failed to remove ephemeral cryptohome with obfuscated username: "
          << dir.obfuscated;
    }
  }

  if (cryptohomes_removed == 0) {
    state = HomeDirs::CryptohomesRemovedStatus::kNone;
  } else if (cryptohomes_removed == homedirs.size()) {
    state = HomeDirs::CryptohomesRemovedStatus::kAll;
  } else {
    state = HomeDirs::CryptohomesRemovedStatus::kSome;
  }

  return state;
}

std::vector<HomeDirs::HomeDir> HomeDirs::GetHomeDirs() {
  std::vector<HomeDirs::HomeDir> ret;
  std::vector<FilePath> entries;
  if (!platform_->EnumerateDirectoryEntries(ShadowRoot(), false, &entries)) {
    return ret;
  }

  for (const auto& entry : entries) {
    HomeDirs::HomeDir dir;
    FilePath basename = entry.BaseName();
    if (!brillo::cryptohome::home::IsSanitizedUserName(basename.value())) {
      continue;
    }
    dir.obfuscated = ObfuscatedUsername(basename.value());
    ret.push_back(dir);
  }

  std::vector<FilePath> user_paths;
  std::transform(
      ret.begin(), ret.end(), std::back_inserter(user_paths),
      [](const HomeDirs::HomeDir& homedir) {
        return brillo::cryptohome::home::GetHashedUserPath(homedir.obfuscated);
      });

  auto is_mounted = platform_->AreDirectoriesMounted(user_paths);

  if (!is_mounted)
    return ret;  // assume all are unmounted

  int i = 0;
  for (const bool& m : is_mounted.value()) {
    ret[i++].is_mounted = m;
  }

  return ret;
}

void HomeDirs::FilterMountedHomedirs(std::vector<HomeDirs::HomeDir>* homedirs) {
  homedirs->erase(std::remove_if(homedirs->begin(), homedirs->end(),
                                 [](const HomeDirs::HomeDir& dir) {
                                   return dir.is_mounted;
                                 }),
                  homedirs->end());
}

bool HomeDirs::GetTrackedDirectory(const FilePath& user_dir,
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

bool HomeDirs::GetTrackedDirectoryForDirCrypto(const FilePath& mount_dir,
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

EncryptedContainerType HomeDirs::ChooseVaultType() {
  // Validate stateful partition logical volume support.
  if (platform_->IsStatefulLogicalVolumeSupported())
    return EncryptedContainerType::kDmcrypt;

  dircrypto::KeyState state = platform_->GetDirCryptoKeyState(ShadowRoot());
  switch (state) {
    case dircrypto::KeyState::NOT_SUPPORTED:
      return EncryptedContainerType::kEcryptfs;
    case dircrypto::KeyState::NO_KEY:
      return EncryptedContainerType::kFscrypt;
    case dircrypto::KeyState::UNKNOWN:
    case dircrypto::KeyState::ENCRYPTED:
      LOG(ERROR) << "Unexpected state " << static_cast<int>(state);
      return EncryptedContainerType::kUnknown;
  }
}

StorageStatusOr<EncryptedContainerType> HomeDirs::GetVaultType(
    const ObfuscatedUsername& obfuscated_username) {
  ASSIGN_OR_RETURN(bool dircrypto_exists,
                   DircryptoCryptohomeExists(obfuscated_username),
                   (_.LogError() << "Can't get vault type"));

  if (EcryptfsCryptohomeExists(obfuscated_username)) {
    if (dircrypto_exists) {
      return EncryptedContainerType::kEcryptfsToFscrypt;
    }
    if (DmcryptCryptohomeExists(obfuscated_username)) {
      return EncryptedContainerType::kEcryptfsToDmcrypt;
    }
    return EncryptedContainerType::kEcryptfs;
  } else if (dircrypto_exists) {
    if (DmcryptCryptohomeExists(obfuscated_username)) {
      return EncryptedContainerType::kFscryptToDmcrypt;
    }
    return EncryptedContainerType::kFscrypt;
  } else if (DmcryptCryptohomeExists(obfuscated_username)) {
    return EncryptedContainerType::kDmcrypt;
  }
  return EncryptedContainerType::kUnknown;
}

StorageStatusOr<EncryptedContainerType> HomeDirs::PickVaultType(
    const ObfuscatedUsername& obfuscated_username,
    const CryptohomeVault::Options& options) {
  // See if the vault exists.
  ASSIGN_OR_RETURN(EncryptedContainerType vault_type,
                   GetVaultType(obfuscated_username));
  // If existing vault is ecryptfs and migrate == true - make migrating vault.
  if (vault_type == EncryptedContainerType::kEcryptfs && options.migrate) {
    if (lvm_migration_enabled_) {
      vault_type = EncryptedContainerType::kEcryptfsToDmcrypt;
    } else {
      vault_type = EncryptedContainerType::kEcryptfsToFscrypt;
    }
  }
  if (vault_type == EncryptedContainerType::kFscrypt && options.migrate) {
    vault_type = EncryptedContainerType::kFscryptToDmcrypt;
  }

  if (vault_type == EncryptedContainerType::kEcryptfs &&
      options.block_ecryptfs) {
    return StorageStatus::Make(FROM_HERE,
                               "Mount attempt with block_ecryptfs on eCryptfs.",
                               MOUNT_ERROR_OLD_ENCRYPTION);
  }

  if (EncryptedContainer::IsMigratingType(vault_type) && !options.migrate) {
    return StorageStatus::Make(
        FROM_HERE,
        "Mount failed because both eCryptfs and dircrypto home"
        " directories were found. Need to resume and finish"
        " migration first.",
        MOUNT_ERROR_PREVIOUS_MIGRATION_INCOMPLETE);
  }

  if (!EncryptedContainer::IsMigratingType(vault_type) && options.migrate) {
    return StorageStatus::Make(
        FROM_HERE, "Mount attempt with migration on non-eCryptfs mount",
        MOUNT_ERROR_UNEXPECTED_MOUNT_TYPE);
  }

  // Vault exists, so we return its type.
  if (vault_type != EncryptedContainerType::kUnknown) {
    return vault_type;
  }

  if (options.migrate) {
    return StorageStatus::Make(
        FROM_HERE, "Can not set up migration for a non-existing vault.",
        MOUNT_ERROR_UNEXPECTED_MOUNT_TYPE);
  }

  if (options.block_ecryptfs) {
    LOG(WARNING) << "Ecryptfs mount block flag has no effect for new vaults.";
  }

  // If there is no existing vault, see if we are asked for a specific type.
  // Otherwise choose the best type based on configuration.
  return options.force_type != EncryptedContainerType::kUnknown
             ? options.force_type
             : ChooseVaultType();
}

bool HomeDirs::GetPlainOwner(Username* owner) {
  LoadDevicePolicy();
  if (!policy_provider_->device_policy_is_loaded())
    return false;
  std::string owner_str;
  policy_provider_->GetDevicePolicy().GetOwner(&owner_str);
  *owner = Username(owner_str);
  return true;
}

bool HomeDirs::GetOwner(ObfuscatedUsername* owner) {
  Username plain_owner;
  if (!GetPlainOwner(&plain_owner) || plain_owner->empty())
    return false;

  *owner = SanitizeUserName(plain_owner);
  return true;
}

bool HomeDirs::IsOrWillBeOwner(const Username& account_id) {
  Username owner;
  GetPlainOwner(&owner);
  return !enterprise_owned() && (owner->empty() || account_id == owner);
}

bool HomeDirs::Create(const Username& username) {
  brillo::ScopedUmask scoped_umask(kDefaultUmask);
  ObfuscatedUsername obfuscated_username = SanitizeUserName(username);

  // Create the user's entry in the shadow root
  FilePath user_dir = UserPath(obfuscated_username);
  if (!platform_->CreateDirectory(user_dir)) {
    return false;
  }

  return true;
}

bool HomeDirs::Remove(const ObfuscatedUsername& obfuscated) {
  remove_callback_.Run(obfuscated);
  FilePath user_dir = UserPath(obfuscated);
  FilePath user_path =
      brillo::cryptohome::home::GetUserPathPrefix().Append(*obfuscated);
  FilePath root_path =
      brillo::cryptohome::home::GetRootPathPrefix().Append(*obfuscated);

  if (platform_->IsDirectoryMounted(user_path) ||
      platform_->IsDirectoryMounted(root_path)) {
    LOG(ERROR) << "Can't remove mounted vault";
    return false;
  }

  bool ret = true;

  if (DmcryptCryptohomeExists(obfuscated)) {
    auto vault = vault_factory_->Generate(obfuscated, FileSystemKeyReference(),
                                          EncryptedContainerType::kDmcrypt);
    ret = vault->Purge();
  }

  return ret && platform_->DeletePathRecursively(user_dir) &&
         platform_->DeletePathRecursively(user_path) &&
         platform_->DeletePathRecursively(root_path);
}

bool HomeDirs::RemoveDmcryptCacheContainer(
    const ObfuscatedUsername& obfuscated) {
  if (!DmcryptCacheContainerExists(obfuscated))
    return false;

  auto vault = vault_factory_->Generate(obfuscated, FileSystemKeyReference(),
                                        EncryptedContainerType::kDmcrypt);
  if (!vault)
    return false;

  if (vault->GetCacheContainerType() != EncryptedContainerType::kDmcrypt)
    return false;

  return vault->PurgeCacheContainer();
}

int64_t HomeDirs::ComputeDiskUsage(const Username& account_id) {
  // SanitizeUserNameWithSalt below doesn't accept empty username.
  if (account_id->empty()) {
    // Empty account is always non-existent, return 0 as specified.
    return 0;
  }

  // Note that for ephemeral mounts, there could be a vault that's not
  // ephemeral, but the current mount is ephemeral. In this case,
  // ComputeDiskUsage() return the non ephemeral on disk vault's size.
  ObfuscatedUsername obfuscated = SanitizeUserName(account_id);
  FilePath user_dir = UserPath(obfuscated);

  int64_t size = 0;
  if (!platform_->DirectoryExists(user_dir)) {
    // It's either ephemeral or the user doesn't exist. In either case, we check
    // /home/user/$hash.
    FilePath user_home_dir = brillo::cryptohome::home::GetUserPath(account_id);
    size = platform_->ComputeDirectoryDiskUsage(user_home_dir);
  } else {
    // Note that we'll need to handle both ecryptfs and dircrypto.
    // dircrypto:
    // /home/.shadow/$hash/mount: Always equal to the size occupied.
    // ecryptfs:
    // /home/.shadow/$hash/vault: Always equal to the size occupied.
    // /home/.shadow/$hash/mount: Equal to the size occupied only when mounted.
    // Therefore, we check to see if vault exists, if it exists, we compute
    // vault's size, otherwise, we check mount's size.
    FilePath mount_dir = user_dir.Append(kMountDir);
    FilePath vault_dir = user_dir.Append(kEcryptfsVaultDir);
    if (platform_->DirectoryExists(vault_dir)) {
      // ecryptfs
      size = platform_->ComputeDirectoryDiskUsage(vault_dir);
    } else {
      // dircrypto
      size = platform_->ComputeDirectoryDiskUsage(mount_dir);
    }
  }
  if (size > 0) {
    return size;
  }
  return 0;
}

namespace {
const char* kChapsDaemonName = "chaps";
}  // namespace

FilePath HomeDirs::GetChapsTokenDir(const Username& user) const {
  return brillo::cryptohome::home::GetDaemonStorePath(user, kChapsDaemonName);
}

bool HomeDirs::NeedsDircryptoMigration(
    const ObfuscatedUsername& obfuscated_username) const {
  // Bail if dircrypto is not supported.
  const dircrypto::KeyState state =
      platform_->GetDirCryptoKeyState(ShadowRoot());
  if (state == dircrypto::KeyState::UNKNOWN ||
      state == dircrypto::KeyState::NOT_SUPPORTED) {
    return false;
  }

  // Use the existence of eCryptfs vault as a single of whether the user needs
  // dircrypto migration. eCryptfs test is adapted from
  // Mount::DoesEcryptfsCryptohomeExist.
  const FilePath user_ecryptfs_vault_dir =
      UserPath(obfuscated_username).Append(kEcryptfsVaultDir);
  return platform_->DirectoryExists(user_ecryptfs_vault_dir);
}

int32_t HomeDirs::GetUnmountedAndroidDataCount() {
  const auto homedirs = GetHomeDirs();

  return std::count_if(
      homedirs.begin(), homedirs.end(), [this](const HomeDirs::HomeDir& dir) {
        if (dir.is_mounted)
          return false;

        if (EcryptfsCryptohomeExists(dir.obfuscated))
          return false;

        FilePath shadow_dir = UserPath(dir.obfuscated);
        FilePath root_home_dir;
        return GetTrackedDirectory(shadow_dir, FilePath(kRootHomeSuffix),
                                   &root_home_dir) &&
               MayContainAndroidData(root_home_dir);
      });
}

bool HomeDirs::MayContainAndroidData(
    const base::FilePath& root_home_dir) const {
  // The root home directory is considered to contain Android data if its
  // grandchild (supposedly android-data/data) is owned by android's system UID.
  std::unique_ptr<FileEnumerator> dir_enum(platform_->GetFileEnumerator(
      root_home_dir, false, base::FileEnumerator::DIRECTORIES));
  for (base::FilePath subdirectory = dir_enum->Next(); !subdirectory.empty();
       subdirectory = dir_enum->Next()) {
    if (LooksLikeAndroidData(subdirectory)) {
      return true;
    }
  }
  return false;
}

bool HomeDirs::LooksLikeAndroidData(const base::FilePath& directory) const {
  std::unique_ptr<FileEnumerator> dir_enum(platform_->GetFileEnumerator(
      directory, false, base::FileEnumerator::DIRECTORIES));

  for (base::FilePath subdirectory = dir_enum->Next(); !subdirectory.empty();
       subdirectory = dir_enum->Next()) {
    if (IsOwnedByAndroidSystem(subdirectory)) {
      return true;
    }
  }
  return false;
}

bool HomeDirs::IsOwnedByAndroidSystem(const base::FilePath& directory) const {
  uid_t uid = 0;
  gid_t gid = 0;
  if (!platform_->GetOwnership(directory, &uid, &gid, false)) {
    return false;
  }
  return uid == kAndroidSystemUid + kArcContainerShiftUid;
}

bool HomeDirs::IsAesKeylockerSupported() {
  // Perform the check only if there's no cached result yet.
  if (!is_aes_keylocker_supported_.has_value()) {
    std::string proc_crypto_contents;
    is_aes_keylocker_supported_ =
        platform_->ReadFileToString(base::FilePath("/proc/crypto"),
                                    &proc_crypto_contents) &&
        proc_crypto_contents.find("aeskl") != std::string::npos;
  }
  return is_aes_keylocker_supported_.value();
}

}  // namespace cryptohome
