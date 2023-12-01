// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/cryptohome_vault_factory.h"

#include <limits>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <base/files/file_path.h>

#include "cryptohome/filesystem_layout.h"
#include "cryptohome/platform.h"
#include "cryptohome/storage/cryptohome_vault.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/encrypted_container_factory.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"

namespace {
// Size of logical volumes to use for the dm-crypt cryptohomes.
constexpr uint64_t kLogicalVolumeSizePercent = 90;
constexpr uint32_t kArcContainerIVOffset = 2823358739;

// By default, each ext4 filesystem takes up ~2% of the entire filesystem space
// for storing filesystem metadata including inode tables. Tune the number of
// inodes such that the overall metadata cost is <1 % of the filesystem size.
// For larger storage devices, we increase the inode count up to an upper limit
// of 2^20 inodes.
uint64_t CalculateInodeCount(int64_t filesystem_size) {
  constexpr uint64_t kGigabytes = 1024 * 1024 * 1024;
  constexpr uint64_t kBaseInodeCount = 256 * 1024;

  if (filesystem_size <= 16 * kGigabytes)
    return kBaseInodeCount;
  if (filesystem_size <= 32 * kGigabytes)
    return 2 * kBaseInodeCount;

  return 4 * kBaseInodeCount;
}

// Get IV offsets for containers.
uint32_t GetContainerIVOffset(const std::string& container_name) {
  // For each container, generate a random 32-bit value to use as the IV offset
  // so that dmcrypt containers (for or compatibility with eMMC Inline
  // Encryption spec, that allows only 32-bit IVs).
  if (container_name == "arcvm") {
    // Make sure that the IVs don't wrap around with 32-bit devices with 128GB
    // storage.
    static_assert(kArcContainerIVOffset < std::numeric_limits<uint32_t>::max() -
                                              128UL * 1024 * 1024 * 2);
    return kArcContainerIVOffset;
  }

  return 0;
}

}  // namespace

namespace cryptohome {

CryptohomeVaultFactory::CryptohomeVaultFactory(
    Platform* platform,
    std::unique_ptr<EncryptedContainerFactory> encrypted_container_factory)
    : platform_(platform),
      encrypted_container_factory_(std::move(encrypted_container_factory)) {}

CryptohomeVaultFactory::~CryptohomeVaultFactory() {}

std::unique_ptr<EncryptedContainer>
CryptohomeVaultFactory::GenerateEncryptedContainer(
    EncryptedContainerType type,
    const ObfuscatedUsername& obfuscated_username,
    const FileSystemKeyReference& key_reference,
    const std::string& container_identifier,
    const DmOptions& dm_options) {
  EncryptedContainerConfig config;
  base::FilePath stateful_device;
  uint64_t stateful_size;

  switch (type) {
    case EncryptedContainerType::kEcryptfs:
      config.backing_dir = GetEcryptfsUserVaultPath(obfuscated_username);
      config.type = EncryptedContainerType::kEcryptfs;
      break;
    case EncryptedContainerType::kFscrypt:
      config.backing_dir = GetUserMountDirectory(obfuscated_username);
      config.type = EncryptedContainerType::kFscrypt;
      break;
    case EncryptedContainerType::kDmcrypt:
      if (!vg_ || !vg_->IsValid() || !thinpool_ || !thinpool_->IsValid())
        return nullptr;

      // Calculate size for dm-crypt partition.
      stateful_device = platform_->GetStatefulDevice();
      if (stateful_device.empty()) {
        PLOG(ERROR) << "Can't get stateful device";
        return nullptr;
      }

      if (!platform_->GetBlkSize(stateful_device, &stateful_size)) {
        PLOG(ERROR) << "Can't get size of stateful device";
        return nullptr;
      }

      LOG_IF(INFO, dm_options.keylocker_enabled)
          << "Using Keylocker for encryption";

      config.type = EncryptedContainerType::kDmcrypt;
      config.dmcrypt_config = {
          .backing_device_config =
              {.type = BackingDeviceType::kLogicalVolumeBackingDevice,
               .name = LogicalVolumePrefix(obfuscated_username) +
                       container_identifier,
               .size = static_cast<int64_t>(
                   (stateful_size * kLogicalVolumeSizePercent) /
                   (100 * 1024 * 1024)),
               .logical_volume = {.vg = vg_, .thinpool = thinpool_}},
          .dmcrypt_device_name =
              DmcryptVolumePrefix(obfuscated_username) + container_identifier,
          .dmcrypt_cipher = dm_options.keylocker_enabled
                                ? "capi:xts-aes-aeskl-plain64"
                                : "aes-xts-plain64",
          .is_raw_device = dm_options.is_raw_device,
          // TODO(sarthakkukreti): Add more dynamic checks for filesystem
          // features once dm-crypt cryptohomes are stable.
          .mkfs_opts = {"-O", "^huge_file,^flex_bg,", "-N",
                        base::StringPrintf("%" PRIu64,
                                           CalculateInodeCount(stateful_size)),
                        "-E", "discard"},
          .tune2fs_opts = {"-O", "verity,quota,project", "-Q",
                           "usrquota,grpquota,prjquota"}};
      break;
    case EncryptedContainerType::kEphemeral:
      config.type = EncryptedContainerType::kEphemeral;
      config.backing_file_name = *obfuscated_username;
      break;
    case EncryptedContainerType::kEcryptfsToFscrypt:
    case EncryptedContainerType::kEcryptfsToDmcrypt:
    case EncryptedContainerType::kFscryptToDmcrypt:
      // The migrating type is handled by the higher level abstraction.
      // FALLTHROUGH
    case EncryptedContainerType::kUnknown:
      LOG(ERROR) << "Incorrect container type: " << static_cast<int>(type);
      return nullptr;
  }

  return encrypted_container_factory_->Generate(config, key_reference);
}

std::unique_ptr<CryptohomeVault> CryptohomeVaultFactory::Generate(
    const ObfuscatedUsername& obfuscated_username,
    const FileSystemKeyReference& key_reference,
    EncryptedContainerType vault_type,
    bool keylocker_enabled) {
  EncryptedContainerType container_type = EncryptedContainerType::kUnknown;
  EncryptedContainerType migrating_container_type =
      EncryptedContainerType::kUnknown;

  if (vault_type == EncryptedContainerType::kEcryptfsToFscrypt) {
    container_type = EncryptedContainerType::kEcryptfs;
    migrating_container_type = EncryptedContainerType::kFscrypt;
  } else if (vault_type == EncryptedContainerType::kEcryptfsToDmcrypt) {
    container_type = EncryptedContainerType::kEcryptfs;
    migrating_container_type = EncryptedContainerType::kDmcrypt;
  } else if (vault_type == EncryptedContainerType::kFscryptToDmcrypt) {
    container_type = EncryptedContainerType::kFscrypt;
    migrating_container_type = EncryptedContainerType::kDmcrypt;
  } else {
    container_type = vault_type;
  }

  // Generate containers for the vault.

  DmOptions vault_dm_options = {
      .keylocker_enabled = keylocker_enabled,
      .is_raw_device = false,
  };
  DmOptions app_dm_options = {
      .keylocker_enabled = keylocker_enabled,
      .is_raw_device = true,
  };

  std::unique_ptr<EncryptedContainer> container = GenerateEncryptedContainer(
      container_type, obfuscated_username, key_reference,
      kDmcryptDataContainerSuffix, vault_dm_options);
  if (!container) {
    LOG(ERROR) << "Could not create vault container";
    return nullptr;
  }

  std::unique_ptr<EncryptedContainer> migrating_container;
  if (migrating_container_type != EncryptedContainerType::kUnknown) {
    migrating_container = GenerateEncryptedContainer(
        migrating_container_type, obfuscated_username, key_reference,
        kDmcryptDataContainerSuffix, vault_dm_options);
    if (!migrating_container) {
      LOG(ERROR) << "Could not create vault container for migration";
      return nullptr;
    }
  }

  std::unique_ptr<EncryptedContainer> cache_container;
  std::unordered_map<std::string, std::unique_ptr<EncryptedContainer>>
      application_containers;
  if (container_type == EncryptedContainerType::kDmcrypt ||
      container_type == EncryptedContainerType::kEcryptfsToDmcrypt ||
      container_type == EncryptedContainerType::kFscryptToDmcrypt) {
    cache_container = GenerateEncryptedContainer(
        container_type, obfuscated_username, key_reference,
        kDmcryptCacheContainerSuffix, vault_dm_options);
    if (!cache_container) {
      LOG(ERROR) << "Could not create vault container for cache";
      return nullptr;
    }
    if (enable_application_containers_) {
      for (const auto& app : std::vector<std::string>{"arcvm"}) {
        app_dm_options.iv_offset = GetContainerIVOffset(app);
        std::unique_ptr<EncryptedContainer> tmp_container =
            GenerateEncryptedContainer(container_type, obfuscated_username,
                                       key_reference, app, app_dm_options);
        if (!tmp_container) {
          LOG(ERROR) << "Could not create vault container for app: " << app;
          return nullptr;
        }
        application_containers[app] = std::move(tmp_container);
      }
    }
  }
  return std::make_unique<CryptohomeVault>(
      obfuscated_username, std::move(container), std::move(migrating_container),
      std::move(cache_container), std::move(application_containers), platform_);
}

void CryptohomeVaultFactory::CacheLogicalVolumeObjects(
    std::optional<brillo::VolumeGroup> vg,
    std::optional<brillo::Thinpool> thinpool) {
  if (!vg || !thinpool) {
    LOG(WARNING) << "Attempting to cache invalid logical volume objects.";
    return;
  }

  vg_ = std::make_shared<brillo::VolumeGroup>(*vg);
  thinpool_ = std::make_shared<brillo::Thinpool>(*thinpool);
}

bool CryptohomeVaultFactory::ContainerExists(const std::string& container) {
  brillo::LogicalVolumeManager* lvm = platform_->GetLogicalVolumeManager();

  if (!vg_ || !vg_->IsValid())
    return false;

  return lvm->GetLogicalVolume(*vg_.get(), container) != std::nullopt;
}

}  // namespace cryptohome
