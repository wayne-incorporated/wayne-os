// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cryptohome/storage/cryptohome_vault.h>

#include <memory>
#include <unordered_map>
#include <utility>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/filesystem_layout.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/encrypted_container/backing_device.h"
#include "cryptohome/storage/encrypted_container/backing_device_factory.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/fake_backing_device.h"
#include "cryptohome/storage/encrypted_container/fake_encrypted_container_factory.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/error.h"
#include "cryptohome/storage/error_test_helpers.h"
#include "cryptohome/storage/keyring/fake_keyring.h"
#include "cryptohome/storage/mock_homedirs.h"

using ::cryptohome::storage::testing::IsError;
using ::hwsec_foundation::error::testing::IsOk;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace cryptohome {

namespace {
struct CryptohomeVaultTestParams {
  CryptohomeVaultTestParams(EncryptedContainerType type,
                            EncryptedContainerType migrating_type,
                            EncryptedContainerType cache_type)
      : container_type(type),
        migrating_container_type(migrating_type),
        cache_container_type(cache_type) {}

  EncryptedContainerType container_type;
  EncryptedContainerType migrating_container_type;
  EncryptedContainerType cache_container_type;
};
}  // namespace

class CryptohomeVaultTest
    : public ::testing::TestWithParam<CryptohomeVaultTestParams> {
 public:
  CryptohomeVaultTest()
      : obfuscated_username_("foo"),
        key_reference_({.fek_sig = brillo::SecureBlob("random keyref")}),
        key_({.fek = brillo::SecureBlob("random key")}),
        backing_dir_(UserPath(obfuscated_username_)),
        keyring_(new FakeKeyring()),
        encrypted_container_factory_(&platform_,
                                     std::unique_ptr<FakeKeyring>(keyring_)) {
    ON_CALL(platform_, SetDirCryptoKey(_, _)).WillByDefault(Return(true));
  }
  ~CryptohomeVaultTest() override = default;

  EncryptedContainerType ContainerType() { return GetParam().container_type; }

  EncryptedContainerType MigratingContainerType() {
    return GetParam().migrating_container_type;
  }

  EncryptedContainerType CacheContainerType() {
    return GetParam().cache_container_type;
  }

  EncryptedContainerConfig ConfigFromType(EncryptedContainerType type,
                                          const std::string& name,
                                          bool is_raw_device) {
    EncryptedContainerConfig config;
    config.type = type;
    switch (type) {
      case EncryptedContainerType::kEcryptfs:
        config.backing_dir = backing_dir_.Append(kEcryptfsVaultDir);
        break;
      case EncryptedContainerType::kFscrypt:
        config.backing_dir = backing_dir_.Append(kMountDir);
        break;
      case EncryptedContainerType::kDmcrypt:
        config = {
            .type = EncryptedContainerType::kDmcrypt,
            .dmcrypt_config = {
                .backing_device_config =
                    {.type = BackingDeviceType::kLogicalVolumeBackingDevice,
                     .name = name,
                     .size = 100 * 1024 * 1024,
                     .logical_volume =
                         {.vg = std::make_shared<brillo::VolumeGroup>("vg",
                                                                      nullptr),
                          .thinpool = std::make_shared<brillo::Thinpool>(
                              "thinpool", "vg", nullptr)}},
                .dmcrypt_device_name = "dmcrypt-" + name,
                .dmcrypt_cipher = "aes-xts-plain64",
                .is_raw_device = is_raw_device,
                .mkfs_opts = {"-O", "^huge_file,^flex_bg,", "-E",
                              "discard,assume_storage_prezeroed=1"},
                .tune2fs_opts = {"-O", "verity,quota", "-Q",
                                 "usrquota,grpquota"}}};
        break;
      default:
        config.type = EncryptedContainerType::kUnknown;
        break;
    }

    return config;
  }

  void ExpectDmcryptSetup(const std::string& name, bool is_raw_device) {
    base::FilePath backing_device_path = base::FilePath("/dev").Append(name);
    base::FilePath dmcrypt_device("/dev/mapper/dmcrypt-" + name);
    EXPECT_CALL(platform_, GetBlkSize(backing_device_path, _))
        .WillOnce(DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
    EXPECT_CALL(platform_, UdevAdmSettle(dmcrypt_device, _))
        .WillOnce(Return(true));
    if (!is_raw_device) {
      EXPECT_CALL(platform_, FormatExt4(_, _, _)).WillRepeatedly(Return(true));
      EXPECT_CALL(platform_, Tune2Fs(dmcrypt_device, _)).WillOnce(Return(true));
    }
  }

  void ExpectContainerSetup(EncryptedContainerType type) {
    switch (type) {
      case EncryptedContainerType::kDmcrypt:
        ExpectDmcryptSetup("data", /*is_raw_device=*/false);
        break;
      default:
        break;
    }
  }

  void ExpectCacheContainerSetup(EncryptedContainerType type) {
    switch (type) {
      case EncryptedContainerType::kDmcrypt:
        ExpectDmcryptSetup("cache", /*is_raw_device=*/false);
        break;
      default:
        break;
    }
  }

  void ExpectApplicationContainerSetup(EncryptedContainerType type) {
    switch (type) {
      case EncryptedContainerType::kDmcrypt:
        ExpectDmcryptSetup("arcvm", /*is_raw_device=*/true);
        ExpectDmcryptSetup("crostini", /*is_raw_device=*/true);
        break;
      default:
        break;
    }
  }

  void ExpectApplicationContainerReset(EncryptedContainerType type) {
    switch (type) {
      case EncryptedContainerType::kDmcrypt:
        EXPECT_CALL(platform_,
                    DiscardDevice(base::FilePath("/dev/mapper/dmcrypt-arcvm")))
            .WillOnce(Return(true));
        EXPECT_CALL(
            platform_,
            DiscardDevice(base::FilePath("/dev/mapper/dmcrypt-crostini")))
            .WillOnce(Return(true));
        break;
      default:
        break;
    }
  }

  void CreateExistingContainer(EncryptedContainerType type) {
    switch (type) {
      case EncryptedContainerType::kEcryptfs:
        platform_.CreateDirectory(backing_dir_.Append(kEcryptfsVaultDir));
        break;
      case EncryptedContainerType::kFscrypt:
        platform_.CreateDirectory(backing_dir_.Append(kMountDir));
        break;
      default:
        break;
    }
  }

  void CheckContainersExist() {
    // For newly created fscrypt containers, add the expectation that fetching
    // the key state returns encrypted.
    if (vault_->container_->GetType() == EncryptedContainerType::kFscrypt ||
        (vault_->migrating_container_ &&
         vault_->migrating_container_->GetType() ==
             EncryptedContainerType::kFscrypt)) {
      EXPECT_CALL(platform_,
                  GetDirCryptoKeyState(backing_dir_.Append(kMountDir)))
          .WillOnce(Return(dircrypto::KeyState::ENCRYPTED));
    }
    EXPECT_TRUE(vault_->container_->Exists());
    if (vault_->migrating_container_) {
      EXPECT_TRUE(vault_->migrating_container_->Exists());
    }
    if (vault_->cache_container_) {
      EXPECT_TRUE(vault_->cache_container_->Exists());
    }

    if (vault_->container_->GetType() == EncryptedContainerType::kDmcrypt) {
      for (auto& [_, container] : vault_->application_containers_) {
        EXPECT_TRUE(container->Exists());
      }
    }
  }

  void ExpectVaultSetup() {
    EXPECT_CALL(platform_, ClearUserKeyring()).WillOnce(Return(true));
    EXPECT_CALL(platform_, SetupProcessKeyring()).WillOnce(Return(true));
  }

  void GenerateVault(bool create_container,
                     bool create_migrating_container,
                     bool create_cache_container,
                     bool create_app_container) {
    std::unique_ptr<EncryptedContainer> container =
        encrypted_container_factory_.Generate(
            ConfigFromType(ContainerType(), "data", /*is_raw_device=*/false),
            key_reference_, create_container);
    if (create_container)
      CreateExistingContainer(ContainerType());

    std::unique_ptr<EncryptedContainer> migrating_container =
        encrypted_container_factory_.Generate(
            ConfigFromType(MigratingContainerType(), "data",
                           /*is_raw_device=*/false),
            key_reference_, create_migrating_container);
    if (create_migrating_container)
      CreateExistingContainer(MigratingContainerType());

    std::unique_ptr<EncryptedContainer> cache_container =
        encrypted_container_factory_.Generate(
            ConfigFromType(CacheContainerType(), "cache",
                           /*is_raw_device=*/false),
            key_reference_, create_cache_container);
    if (create_cache_container)
      CreateExistingContainer(CacheContainerType());

    std::unordered_map<std::string, std::unique_ptr<EncryptedContainer>>
        application_containers;

    if (ContainerType() == EncryptedContainerType::kDmcrypt) {
      application_containers["arcvm"] = encrypted_container_factory_.Generate(
          ConfigFromType(CacheContainerType(), "arcvm", /*is_raw_device=*/
                         true),
          key_reference_, create_app_container);

      application_containers["crostini"] =
          encrypted_container_factory_.Generate(
              ConfigFromType(CacheContainerType(),
                             "crostini", /*is_raw_device=*/
                             true),
              key_reference_, create_app_container);
    }

    vault_ = std::make_unique<CryptohomeVault>(
        obfuscated_username_, std::move(container),
        std::move(migrating_container), std::move(cache_container),
        std::move(application_containers), &platform_);
  }

  bool ResetApplicationContainer(const std::string& app) {
    if (ContainerType() != EncryptedContainerType::kDmcrypt)
      return true;
    return vault_->ResetApplicationContainer(app);
  }

 protected:
  const ObfuscatedUsername obfuscated_username_;
  const FileSystemKeyReference key_reference_;
  const FileSystemKey key_;
  const base::FilePath backing_dir_;

  MockHomeDirs homedirs_;
  MockPlatform platform_;
  FakeKeyring* keyring_;
  FakeEncryptedContainerFactory encrypted_container_factory_;
  std::unique_ptr<CryptohomeVault> vault_;
};

INSTANTIATE_TEST_SUITE_P(WithEcryptfs,
                         CryptohomeVaultTest,
                         ::testing::Values(CryptohomeVaultTestParams(
                             EncryptedContainerType::kEcryptfs,
                             EncryptedContainerType::kUnknown,
                             EncryptedContainerType::kUnknown)));
INSTANTIATE_TEST_SUITE_P(WithFscrypt,
                         CryptohomeVaultTest,
                         ::testing::Values(CryptohomeVaultTestParams(
                             EncryptedContainerType::kFscrypt,
                             EncryptedContainerType::kUnknown,
                             EncryptedContainerType::kUnknown)));
INSTANTIATE_TEST_SUITE_P(WithFscryptMigration,
                         CryptohomeVaultTest,
                         ::testing::Values(CryptohomeVaultTestParams(
                             EncryptedContainerType::kEcryptfs,
                             EncryptedContainerType::kFscrypt,
                             EncryptedContainerType::kUnknown)));

INSTANTIATE_TEST_SUITE_P(WithDmcrypt,
                         CryptohomeVaultTest,
                         ::testing::Values(CryptohomeVaultTestParams(
                             EncryptedContainerType::kDmcrypt,
                             EncryptedContainerType::kUnknown,
                             EncryptedContainerType::kDmcrypt)));

// Tests failure path on failure to setup process keyring for eCryptfs and
// fscrypt.
TEST_P(CryptohomeVaultTest, FailedProcessKeyringSetup) {
  GenerateVault(/*create_container=*/false,
                /*create_migrating_container=*/false,
                /*create_cache_container=*/false,
                /*create_app_container=*/false);
  EXPECT_CALL(platform_, SetupProcessKeyring()).WillOnce(Return(false));
  EXPECT_THAT(vault_->Setup(key_),
              IsError(MOUNT_ERROR_SETUP_PROCESS_KEYRING_FAILED));
}

// Tests the failure path on Setup if setting up the container fails.
TEST_P(CryptohomeVaultTest, ContainerSetupFailed) {
  GenerateVault(/*create_container=*/false,
                /*create_migrating_container=*/false,
                /*create_cache_container=*/false,
                /*create_app_container=*/false);
  ExpectVaultSetup();
  keyring_->SetShouldFail(true);
  EXPECT_THAT(vault_->Setup(key_), IsError(MOUNT_ERROR_KEYRING_FAILED));
}

// Tests the failure path on Setup if setting up the container fails.
TEST_P(CryptohomeVaultTest, MigratingContainerSetupFailed) {
  GenerateVault(/*create_container=*/false,
                /*create_migrating_container=*/false,
                /*create_cache_container=*/false,
                /*create_app_container=*/false);
  ExpectVaultSetup();
  ExpectContainerSetup(ContainerType());
  ExpectCacheContainerSetup(CacheContainerType());
  ExpectApplicationContainerSetup(ContainerType());

  // In absence of a migrating container, the vault setup should succeed.
  int good_key_calls = 1;
  if (ContainerType() == EncryptedContainerType::kDmcrypt) {
    good_key_calls = 8;
  } else if (CacheContainerType() != EncryptedContainerType::kUnknown) {
    good_key_calls = 2;
  }
  keyring_->SetShouldFailAfter(good_key_calls);

  if (MigratingContainerType() != EncryptedContainerType::kUnknown) {
    EXPECT_THAT(vault_->Setup(key_), IsError(MOUNT_ERROR_KEYRING_FAILED));
  } else {
    EXPECT_THAT(vault_->Setup(key_), IsOk());
  }
}

// Tests the setup path of a pristine cryptohome.
TEST_P(CryptohomeVaultTest, CreateVault) {
  GenerateVault(/*create_container=*/false,
                /*create_migrating_container=*/false,
                /*create_cache_container=*/false,
                /*create_app_container=*/false);
  ExpectVaultSetup();
  ExpectContainerSetup(ContainerType());
  ExpectContainerSetup(MigratingContainerType());
  ExpectCacheContainerSetup(CacheContainerType());
  ExpectApplicationContainerSetup(ContainerType());

  EXPECT_THAT(vault_->Setup(key_), IsOk());

  CheckContainersExist();
}

// Tests the setup path for an existing container with no migrating container
// setup.
TEST_P(CryptohomeVaultTest, ExistingVaultNoMigratingVault) {
  GenerateVault(/*create_container=*/true,
                /*create_migrating_container=*/false,
                /*create_cache_container=*/false,
                /*create_app_container=*/false);
  ExpectVaultSetup();
  ExpectContainerSetup(ContainerType());
  ExpectContainerSetup(MigratingContainerType());
  ExpectCacheContainerSetup(CacheContainerType());
  ExpectApplicationContainerSetup(ContainerType());

  EXPECT_THAT(vault_->Setup(key_), IsOk());

  CheckContainersExist();
}

// Tests the setup path for an existing vault with an existing migrating
// container (incomplete migration).
TEST_P(CryptohomeVaultTest, ExistingMigratingVault) {
  GenerateVault(/*create_container=*/true, /*create_migrating_container=*/true,
                /*create_cache_container=*/false,
                /*create_app_container=*/false);
  ExpectVaultSetup();
  ExpectContainerSetup(ContainerType());
  ExpectContainerSetup(MigratingContainerType());
  ExpectCacheContainerSetup(CacheContainerType());
  ExpectApplicationContainerSetup(ContainerType());

  EXPECT_THAT(vault_->Setup(key_), IsOk());

  CheckContainersExist();
}

// Tests the setup path for an existing vault with an existing cache container.
TEST_P(CryptohomeVaultTest, ExistingCacheContainer) {
  GenerateVault(/*create_container=*/true, /*create_migrating_container=*/false,
                /*create_cache_container=*/true,
                /*create_app_container=*/false);
  ExpectVaultSetup();
  ExpectContainerSetup(ContainerType());
  ExpectContainerSetup(MigratingContainerType());
  ExpectCacheContainerSetup(CacheContainerType());
  ExpectApplicationContainerSetup(ContainerType());

  EXPECT_THAT(vault_->Setup(key_), IsOk());

  CheckContainersExist();
}

// Tests the setup path for an existing vault with an existing application
// containers.
TEST_P(CryptohomeVaultTest, ExistingApplicationContainers) {
  GenerateVault(/*create_container=*/true, /*create_migrating_container=*/false,
                /*create_cache_container=*/false,
                /*create_app_container=*/true);
  ExpectVaultSetup();
  ExpectContainerSetup(ContainerType());
  ExpectContainerSetup(MigratingContainerType());
  ExpectCacheContainerSetup(CacheContainerType());
  ExpectApplicationContainerSetup(ContainerType());

  EXPECT_THAT(vault_->Setup(key_), IsOk());

  CheckContainersExist();
}

// Tests the reset path for application containers in a cryptohome vault.
TEST_P(CryptohomeVaultTest, ResetApplicationContainer) {
  GenerateVault(/*create_container=*/true, /*create_migrating_container=*/false,
                /*create_cache_container=*/false,
                /*create_app_container=*/true);

  ExpectVaultSetup();
  ExpectContainerSetup(ContainerType());
  ExpectContainerSetup(MigratingContainerType());
  ExpectCacheContainerSetup(CacheContainerType());
  ExpectApplicationContainerSetup(ContainerType());

  EXPECT_THAT(vault_->Setup(key_), IsOk());

  ExpectApplicationContainerReset(ContainerType());
  EXPECT_TRUE(ResetApplicationContainer("arcvm"));
  EXPECT_TRUE(ResetApplicationContainer("crostini"));

  CheckContainersExist();
}

}  // namespace cryptohome
