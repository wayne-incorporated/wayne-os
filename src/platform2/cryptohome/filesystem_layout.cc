// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/filesystem_layout.h"

#include <string>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/cryptohome.h>
#include <brillo/secure_blob.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>

#include "cryptohome/auth_factor/auth_factor_label.h"
#include "cryptohome/cryptohome_common.h"
#include "cryptohome/cryptohome_metrics.h"
#include "cryptohome/platform.h"
#include "cryptohome/username.h"

using ::hwsec_foundation::CreateSecureRandomBlob;

namespace cryptohome {
namespace {

constexpr char kShadowRoot[] = "/home/.shadow";

constexpr char kSystemSaltFile[] = "salt";
constexpr int64_t kSystemSaltMaxSize = (1 << 20);  // 1 MB
constexpr mode_t kSaltFilePermissions = 0644;

constexpr char kSkelPath[] = "/etc/skel";
constexpr char kLogicalVolumePrefix[] = "cryptohome";
constexpr char kDmcryptVolumePrefix[] = "dmcrypt";

// Storage for serialized RecoveryId.
constexpr char kRecoveryIdFile[] = "recovery_id";

// The directory where flag files live.
constexpr char kFlagFileRoot[] = "/var/lib/cryptohome";

bool GetOrCreateSalt(Platform* platform,
                     const base::FilePath& salt_file,
                     brillo::SecureBlob* salt) {
  int64_t file_len = 0;
  if (platform->FileExists(salt_file)) {
    if (!platform->GetFileSize(salt_file, &file_len)) {
      LOG(ERROR) << "Can't get file len for " << salt_file.value();
      return false;
    }
  }
  brillo::SecureBlob local_salt;
  if (file_len == 0 || file_len > kSystemSaltMaxSize) {
    LOG(ERROR) << "Creating new salt at " << salt_file.value() << " ("
               << file_len << ")";
    // If this salt doesn't exist, automatically create it.
    local_salt = CreateSecureRandomBlob(CRYPTOHOME_DEFAULT_SALT_LENGTH);
    if (!platform->WriteSecureBlobToFileAtomicDurable(salt_file, local_salt,
                                                      kSaltFilePermissions)) {
      LOG(ERROR) << "Could not write user salt";
      return false;
    }
  } else {
    local_salt.resize(file_len);
    if (!platform->ReadFileToSecureBlob(salt_file, &local_salt)) {
      LOG(ERROR) << "Could not read salt file of length " << file_len;
      return false;
    }
  }
  if (salt) {
    salt->swap(local_salt);
  }
  return true;
}

// Get the Account ID for an AccountIdentifier proto.
Username GetAccountId(const AccountIdentifier& id) {
  if (id.has_account_id()) {
    return Username(id.account_id());
  }
  return Username(id.email());
}

}  // namespace

base::FilePath ShadowRoot() {
  return base::FilePath(kShadowRoot);
}

base::FilePath SystemSaltFile() {
  return ShadowRoot().Append(kSystemSaltFile);
}

base::FilePath PublicMountSaltFile() {
  return base::FilePath(kPublicMountSaltFilePath);
}

base::FilePath SkelDir() {
  return base::FilePath(kSkelPath);
}

base::FilePath UserPath(const ObfuscatedUsername& obfuscated) {
  return ShadowRoot().Append(*obfuscated);
}

base::FilePath VaultKeysetPath(const ObfuscatedUsername& obfuscated,
                               int index) {
  return UserPath(obfuscated)
      .Append(kKeyFile)
      .AddExtension(base::NumberToString(index));
}

base::FilePath UserSecretStashPath(
    const ObfuscatedUsername& obfuscated_username, int slot) {
  DCHECK_GE(slot, 0);
  return UserPath(obfuscated_username)
      .Append(kUserSecretStashDir)
      .Append(kUserSecretStashFileBase)
      .AddExtension(std::to_string(slot));
}

base::FilePath AuthFactorsDirPath(
    const ObfuscatedUsername& obfuscated_username) {
  return UserPath(obfuscated_username).Append(kAuthFactorsDir);
}

base::FilePath AuthFactorPath(const ObfuscatedUsername& obfuscated_username,
                              const std::string& auth_factor_type_string,
                              const std::string& auth_factor_label) {
  // The caller must make sure the label was sanitized.
  DCHECK(IsValidAuthFactorLabel(auth_factor_label));
  return UserPath(obfuscated_username)
      .Append(kAuthFactorsDir)
      .Append(auth_factor_type_string)
      .AddExtension(auth_factor_label);
}

base::FilePath UserActivityPerIndexTimestampPath(
    const ObfuscatedUsername& obfuscated, int index) {
  return VaultKeysetPath(obfuscated, index).AddExtension(kTsFile);
}

base::FilePath UserActivityTimestampPath(const ObfuscatedUsername& obfuscated) {
  return UserPath(obfuscated).Append(kTsFile);
}

base::FilePath GetEcryptfsUserVaultPath(const ObfuscatedUsername& obfuscated) {
  return UserPath(obfuscated).Append(kEcryptfsVaultDir);
}

base::FilePath GetUserMountDirectory(
    const ObfuscatedUsername& obfuscated_username) {
  return UserPath(obfuscated_username).Append(kMountDir);
}

base::FilePath GetUserTemporaryMountDirectory(
    const ObfuscatedUsername& obfuscated_username) {
  return UserPath(obfuscated_username).Append(kTemporaryMountDir);
}

base::FilePath GetDmcryptUserCacheDirectory(
    const ObfuscatedUsername& obfuscated_username) {
  return UserPath(obfuscated_username).Append(kDmcryptCacheDir);
}

std::string LogicalVolumePrefix(const ObfuscatedUsername& obfuscated_username) {
  return std::string(kLogicalVolumePrefix) + "-" +
         obfuscated_username->substr(0, 8) + "-";
}

std::string DmcryptVolumePrefix(const ObfuscatedUsername& obfuscated_username) {
  return std::string(kDmcryptVolumePrefix) + "-" +
         obfuscated_username->substr(0, 8) + "-";
}

base::FilePath GetDmcryptDataVolume(
    const ObfuscatedUsername& obfuscated_username) {
  return base::FilePath(kDeviceMapperDir)
      .Append(DmcryptVolumePrefix(obfuscated_username)
                  .append(kDmcryptDataContainerSuffix));
}

base::FilePath GetDmcryptCacheVolume(
    const ObfuscatedUsername& obfuscated_username) {
  return base::FilePath(kDeviceMapperDir)
      .Append(DmcryptVolumePrefix(obfuscated_username)
                  .append(kDmcryptCacheContainerSuffix));
}

bool GetSystemSalt(Platform* platform, brillo::SecureBlob* salt) {
  return GetOrCreateSalt(platform, SystemSaltFile(), salt);
}

bool GetPublicMountSalt(Platform* platform, brillo::SecureBlob* salt) {
  return GetOrCreateSalt(platform, PublicMountSaltFile(), salt);
}

base::FilePath GetRecoveryIdPath(const AccountIdentifier& account_id) {
  ObfuscatedUsername obfuscated =
      brillo::cryptohome::home::SanitizeUserName(GetAccountId(account_id));
  if (obfuscated->empty()) {
    return base::FilePath();
  }
  return brillo::cryptohome::home::GetHashedUserPath(obfuscated)
      .Append(kRecoveryIdFile);
}

bool InitializeFilesystemLayout(Platform* platform, brillo::SecureBlob* salt) {
  const base::FilePath shadow_root = ShadowRoot();
  if (!platform->DirectoryExists(shadow_root)) {
    platform->CreateDirectory(shadow_root);
    if (platform->RestoreSELinuxContexts(shadow_root, true /*recursive*/)) {
      ReportRestoreSELinuxContextResultForShadowDir(true);
    } else {
      ReportRestoreSELinuxContextResultForShadowDir(false);
      LOG(ERROR) << "RestoreSELinuxContexts(" << shadow_root << ") failed.";
    }
  }

  if (!GetSystemSalt(platform, salt)) {
    LOG(ERROR) << "Failed to create system salt.";
    return false;
  }
  return true;
}

bool DoesFlagFileExist(const std::string& name, Platform* platform) {
  // Reject the name if it's an absolute path.
  base::FilePath flag_file_name(name);
  if (flag_file_name.IsAbsolute()) {
    LOG(ERROR) << "attempted reading an absolute path as a flag file: " << name;
    return false;
  }
  // Construct the full path of the flag file.
  base::FilePath flag_file_dir(kFlagFileRoot);
  base::FilePath flag_file_path = flag_file_dir.Append(flag_file_name);
  // Verify that the name was actually a name and not a relative path. This is
  // done by converting the path into an absolute path and verifying that the
  // dirname is still kFlagFileRoot.
  std::optional<base::FilePath> absolute_path =
      base::MakeAbsoluteFilePathNoResolveSymbolicLinks(flag_file_path);
  if (!absolute_path || absolute_path->DirName() != flag_file_dir) {
    LOG(ERROR) << "attempted reading a relative path as a flag file: " << name;
    return false;
  }
  // The path is "safe" so check that it exists.
  return platform->FileExists(flag_file_path);
}

}  // namespace cryptohome
