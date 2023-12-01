// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mount_encrypted/encrypted_fs.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>
#include <brillo/blkdev_utils/device_mapper_fake.h>

#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/encrypted_container/backing_device.h"
#include "cryptohome/storage/encrypted_container/dmcrypt_container.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/fake_backing_device.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/keyring/fake_keyring.h"
#include "cryptohome/storage/keyring/utils.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace mount_encrypted {

class EncryptedFsTest : public ::testing::Test {
 public:
  EncryptedFsTest()
      : dmcrypt_name_("encstateful"),
        dmcrypt_device_(base::FilePath("/dev/mapper/encstateful")),
        mount_point_(base::FilePath("/mnt/stateful_partition/encrypted")),
        config_({.backing_device_config =
                     {.type = cryptohome::BackingDeviceType::kLoopbackDevice,
                      .name = "encstateful"},
                 .dmcrypt_device_name = dmcrypt_name_,
                 .dmcrypt_cipher = "aes-cbc-essiv:sha256",
                 .mkfs_opts = {"-O", "encrypt,verity"},
                 .tune2fs_opts = {"-Q", "project"}}),
        device_mapper_(base::BindRepeating(&brillo::fake::CreateDevmapperTask)),
        fake_backing_device_factory_(&platform_) {
    // Set up a fake backing device.
    auto fake_backing_device =
        fake_backing_device_factory_.Generate(config_.backing_device_config);
    backing_device_ = fake_backing_device.get();

    // Set encryption key.
    brillo::SecureBlob secret;
    brillo::SecureBlob::HexStringToSecureBlob("0123456789ABCDEF", &secret);
    key_.fek = secret;
    key_reference_ = cryptohome::dmcrypt::GenerateKeyringDescription(
        brillo::SecureBlob("some ref"));
    key_descriptor_ = cryptohome::dmcrypt::GenerateDmcryptKeyDescriptor(
        key_reference_.fek_sig, key_.fek.size());

    auto container = std::make_unique<cryptohome::DmcryptContainer>(
        config_, std::move(fake_backing_device), key_reference_, &platform_,
        &keyring_,
        std::make_unique<brillo::DeviceMapper>(
            base::BindRepeating(&brillo::fake::CreateDevmapperTask)));

    encrypted_fs_ = std::make_unique<EncryptedFs>(
        base::FilePath("/"), 3UL * 1024 * 1024 * 1024, dmcrypt_name_,
        std::move(container), &platform_, &device_mapper_);
  }
  ~EncryptedFsTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(
        platform_.CreateDirectory(base::FilePath("/mnt/stateful_partition/")));
    ASSERT_TRUE(platform_.CreateDirectory(base::FilePath("/var")));
    ASSERT_TRUE(platform_.CreateDirectory(base::FilePath("/home/chronos")));
  }

  void ExpectSetup(bool is_formatted) {
    EXPECT_CALL(platform_, GetBlkSize(_, _))
        .WillRepeatedly(DoAll(SetArgPointee<1>(40920000), Return(true)));
    EXPECT_CALL(platform_, UdevAdmSettle(_, _)).WillOnce(Return(true));
    EXPECT_CALL(platform_, Tune2Fs(_, _)).WillOnce(Return(true));
  }

  void ExpectCreate() {
    EXPECT_CALL(platform_, FormatExt4(dmcrypt_device_, _, _))
        .WillOnce(Return(true));
  }

 protected:
  const std::string dmcrypt_name_;
  const base::FilePath dmcrypt_device_;
  const base::FilePath mount_point_;
  cryptohome::DmcryptConfig config_;

  NiceMock<cryptohome::MockPlatform> platform_;
  cryptohome::FakeKeyring keyring_;
  brillo::DeviceMapper device_mapper_;
  cryptohome::FakeBackingDeviceFactory fake_backing_device_factory_;
  cryptohome::FileSystemKey key_;
  cryptohome::FileSystemKeyReference key_reference_;
  brillo::SecureBlob key_descriptor_;
  cryptohome::BackingDevice* backing_device_;
  std::unique_ptr<EncryptedFs> encrypted_fs_;
};

TEST_F(EncryptedFsTest, RebuildStateful) {
  ExpectSetup(/*is_formatted=*/false);
  ExpectCreate();

  // Check if dm device is mounted and has the correct key.
  EXPECT_EQ(encrypted_fs_->Setup(key_, true), RESULT_SUCCESS);

  // Check that the dm-crypt device is created and has the correct key.
  brillo::DevmapperTable table =
      encrypted_fs_->device_mapper_->GetTable(dmcrypt_name_);
  EXPECT_EQ(table.CryptGetKey(), key_descriptor_);
  // Check if backing device is attached.
  EXPECT_EQ(backing_device_->GetPath(), base::FilePath("/dev/encstateful"));

  EXPECT_EQ(encrypted_fs_->Teardown(), RESULT_SUCCESS);

  // Make sure no devmapper device is left.
  EXPECT_EQ(device_mapper_.GetTable(dmcrypt_name_).CryptGetKey(),
            brillo::SecureBlob());
  // Check if backing device is not attached.
  EXPECT_EQ(backing_device_->GetPath(), std::nullopt);
}

TEST_F(EncryptedFsTest, OldStateful) {
  ExpectSetup(/*is_formatted=*/true);

  // Create the fake backing device.
  ASSERT_TRUE(backing_device_->Create());

  // Expect setup to succeed.
  EXPECT_EQ(encrypted_fs_->Setup(key_, false), RESULT_SUCCESS);
  // Check that the dm-crypt device is created and has the correct key.
  brillo::DevmapperTable table =
      encrypted_fs_->device_mapper_->GetTable(dmcrypt_name_);
  EXPECT_EQ(table.CryptGetKey(), key_descriptor_);
  // Check if backing device is attached.
  EXPECT_EQ(backing_device_->GetPath(), base::FilePath("/dev/encstateful"));

  EXPECT_EQ(encrypted_fs_->Teardown(), RESULT_SUCCESS);
  // Make sure no devmapper device is left.
  EXPECT_EQ(device_mapper_.GetTable(dmcrypt_name_).CryptGetKey(),
            brillo::SecureBlob());
  // Check if backing device is not attached.
  EXPECT_EQ(backing_device_->GetPath(), std::nullopt);
}

TEST_F(EncryptedFsTest, LoopdevTeardown) {
  // BlkSize == 0 --> Teardown loopdev
  EXPECT_CALL(platform_, GetBlkSize(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(0), Return(true)));

  // Create the fake backing device.
  ASSERT_TRUE(backing_device_->Create());
  // Expect setup to fail.
  EXPECT_EQ(encrypted_fs_->Setup(key_, false), RESULT_FAIL_FATAL);
  // Make sure that the backing device is not left attached.
  EXPECT_EQ(backing_device_->GetPath(), std::nullopt);
}

TEST_F(EncryptedFsTest, DevmapperTeardown) {
  // Mount failed --> Teardown devmapper
  ExpectSetup(/*is_formatted=*/true);
  EXPECT_CALL(platform_, Mount(_, _, _, _, _)).WillOnce(Return(false));

  // Create the fake backing device.
  ASSERT_TRUE(backing_device_->Create());
  // Expect setup to fail.
  EXPECT_EQ(encrypted_fs_->Setup(key_, false), RESULT_FAIL_FATAL);
  // Make sure that the backing device is no left attached.
  EXPECT_EQ(backing_device_->GetPath(), std::nullopt);
}

}  // namespace mount_encrypted
