// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_FILESYSTEM_LAYOUT_H_
#define CRYPTOHOME_FILESYSTEM_LAYOUT_H_

#include <string>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>

#include "cryptohome/platform.h"
#include "cryptohome/proto_bindings/rpc.pb.h"
#include "cryptohome/username.h"

namespace cryptohome {

// Name of the vault directory which is used with eCryptfs cryptohome.
inline constexpr char kEcryptfsVaultDir[] = "vault";
// Name of the mount directory.
inline constexpr char kMountDir[] = "mount";
// Name of the temporary mount directory used during migration.
inline constexpr char kTemporaryMountDir[] = "temporary_mount";
// Name of the dm-crypt cache directory.
inline constexpr char kDmcryptCacheDir[] = "cache";
// Device Mapper directory.
inline constexpr char kDeviceMapperDir[] = "/dev/mapper";

// Suffix for cryptohome dm-crypt container.
inline constexpr char kDmcryptCacheContainerSuffix[] = "cache";
inline constexpr char kDmcryptDataContainerSuffix[] = "data";

inline constexpr mode_t kKeyFilePermissions = 0600;
inline constexpr int kKeyFileMax = 100;  // master.0 ... master.99 // nocheck
inline constexpr char kKeyFile[] = "master";  // nocheck
inline constexpr char kKeyLegacyPrefix[] = "legacy-";

inline constexpr int kInitialKeysetIndex = 0;
inline constexpr char kTsFile[] = "timestamp";

inline constexpr char kDmcryptContainerMountType[] = "ext4";
inline constexpr char kDmcryptContainerMountOptions[] = "discard,commit=600";

inline constexpr char kUserSecretStashDir[] = "user_secret_stash";
inline constexpr char kUserSecretStashFileBase[] = "uss";
inline constexpr int kUserSecretStashDefaultSlot = 0;
inline constexpr char kAuthFactorsDir[] = "auth_factors";

base::FilePath ShadowRoot();
base::FilePath SystemSaltFile();
base::FilePath PublicMountSaltFile();
base::FilePath SkelDir();
base::FilePath UserPath(const ObfuscatedUsername& obfuscated);
base::FilePath VaultKeysetPath(const ObfuscatedUsername& obfuscated, int index);
base::FilePath UserActivityPerIndexTimestampPath(
    const ObfuscatedUsername& obfuscated, int index);
base::FilePath UserActivityTimestampPath(const ObfuscatedUsername& obfuscated);
base::FilePath UserSecretStashPath(
    const ObfuscatedUsername& obfuscated_username, int slot);
base::FilePath AuthFactorsDirPath(
    const ObfuscatedUsername& obfuscated_username);
base::FilePath AuthFactorPath(const ObfuscatedUsername& obfuscated_username,
                              const std::string& auth_factor_type_string,
                              const std::string& auth_factor_label);

std::string LogicalVolumePrefix(const ObfuscatedUsername& obfuscated_username);
std::string DmcryptVolumePrefix(const ObfuscatedUsername& obfuscated_username);

base::FilePath GetEcryptfsUserVaultPath(
    const ObfuscatedUsername& obfuscated_username);
base::FilePath GetUserMountDirectory(
    const ObfuscatedUsername& obfuscated_username);
base::FilePath GetUserTemporaryMountDirectory(
    const ObfuscatedUsername& obfuscated_username);
base::FilePath GetDmcryptUserCacheDirectory(
    const ObfuscatedUsername& obfuscated_username);
base::FilePath GetDmcryptDataVolume(
    const ObfuscatedUsername& obfuscated_username);
base::FilePath GetDmcryptCacheVolume(
    const ObfuscatedUsername& obfuscated_username);

// Gets existing system salt, or creates one if it doesn't exist.
bool GetSystemSalt(Platform* platform, brillo::SecureBlob* salt);

// Gets an existing kiosk mount salt, or creates one if it doesn't exist.
bool GetPublicMountSalt(Platform* platform, brillo::SecureBlob* salt);

// Gets full path for serialized RecoveryId.
base::FilePath GetRecoveryIdPath(const AccountIdentifier& account_id);

bool InitializeFilesystemLayout(Platform* platform, brillo::SecureBlob* salt);

// Checks if a given named flag file exists. The name must be a filename and
// cannot be an arbitrary path.
bool DoesFlagFileExist(const std::string& name, Platform* platform);

}  // namespace cryptohome

#endif  // CRYPTOHOME_FILESYSTEM_LAYOUT_H_
