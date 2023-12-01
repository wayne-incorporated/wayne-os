// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/encrypted_container/dmcrypt_container.h"

#include <memory>
#include <string>
#include <utility>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/files/file_path.h>
#include <base/functional/bind.h>
#include <brillo/blkdev_utils/device_mapper_fake.h>
#include <brillo/secure_blob.h>

#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/fake_backing_device.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/keyring/fake_keyring.h"
#include "cryptohome/storage/keyring/utils.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;

namespace cryptohome {

class DmcryptContainerTest : public ::testing::Test {
 public:
  DmcryptContainerTest()
      : config_({.dmcrypt_device_name = "crypt_device",
                 .dmcrypt_cipher = "aes-xts-plain64",
                 .mkfs_opts = {"-O", "encrypt,verity"},
                 .tune2fs_opts = {"-Q", "project"}}),
        key_({.fek = brillo::SecureBlob("random key")}),
        key_reference_({.fek_sig = brillo::SecureBlob("random reference")}),
        device_mapper_(base::BindRepeating(&brillo::fake::CreateDevmapperTask)),
        backing_device_(std::make_unique<FakeBackingDevice>(
            BackingDeviceType::kLogicalVolumeBackingDevice,
            base::FilePath("/dev/VG/LV"))) {
    key_reference_ =
        dmcrypt::GenerateKeyringDescription(key_reference_.fek_sig);
    key_descriptor_ = dmcrypt::GenerateDmcryptKeyDescriptor(
        key_reference_.fek_sig, key_.fek.size());
  }
  ~DmcryptContainerTest() override = default;

  void SetIsRawDevice(bool value) { config_.is_raw_device = value; }

  void GenerateContainer() {
    container_ = std::make_unique<DmcryptContainer>(
        config_, std::move(backing_device_), key_reference_, &platform_,
        &keyring_,
        std::make_unique<brillo::DeviceMapper>(
            base::BindRepeating(&brillo::fake::CreateDevmapperTask)));
  }

 protected:
  DmcryptConfig config_;

  FileSystemKey key_;
  FileSystemKeyReference key_reference_;
  MockPlatform platform_;
  FakeKeyring keyring_;
  brillo::DeviceMapper device_mapper_;
  std::unique_ptr<BackingDevice> backing_device_;
  std::unique_ptr<DmcryptContainer> container_;
  brillo::SecureBlob key_descriptor_;
};

// Tests the creation path for the dm-crypt container.
TEST_F(DmcryptContainerTest, SetupCreateCheck) {
  EXPECT_CALL(platform_, GetBlkSize(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
  EXPECT_CALL(platform_, UdevAdmSettle(_, _)).WillOnce(Return(true));
  EXPECT_CALL(platform_, FormatExt4(_, _, _)).WillOnce(Return(true));
  EXPECT_CALL(platform_, Tune2Fs(_, _)).WillOnce(Return(true));

  GenerateContainer();

  EXPECT_TRUE(container_->Setup(key_));
  // Check that the device mapper target exists.
  EXPECT_EQ(device_mapper_.GetTable(config_.dmcrypt_device_name).CryptGetKey(),
            key_descriptor_);
  EXPECT_TRUE(device_mapper_.Remove(config_.dmcrypt_device_name));
}

// Tests the creation path for the dm-crypt container with raw device only.
TEST_F(DmcryptContainerTest, SetupCreateRawCheck) {
  EXPECT_CALL(platform_, GetBlkSize(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
  EXPECT_CALL(platform_, UdevAdmSettle(_, _)).WillOnce(Return(true));
  EXPECT_CALL(platform_, FormatExt4(_, _, _)).Times(0);
  EXPECT_CALL(platform_, Tune2Fs(_, _)).Times(0);

  config_.is_raw_device = true;

  GenerateContainer();

  EXPECT_TRUE(container_->Setup(key_));
  // Check that the device mapper target exists.
  EXPECT_EQ(device_mapper_.GetTable(config_.dmcrypt_device_name).CryptGetKey(),
            key_descriptor_);
  EXPECT_TRUE(device_mapper_.Remove(config_.dmcrypt_device_name));
}

// Tests the setup path with an existing container.
TEST_F(DmcryptContainerTest, SetupNoCreateCheck) {
  EXPECT_CALL(platform_, GetBlkSize(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
  EXPECT_CALL(platform_, UdevAdmSettle(_, _)).WillOnce(Return(true));
  EXPECT_CALL(platform_, Tune2Fs(_, _)).WillOnce(Return(true));

  backing_device_->Create();
  GenerateContainer();

  EXPECT_TRUE(container_->Setup(key_));
  // Check that the device mapper target exists.
  EXPECT_EQ(device_mapper_.GetTable(config_.dmcrypt_device_name).CryptGetKey(),
            key_descriptor_);
  EXPECT_TRUE(device_mapper_.Remove(config_.dmcrypt_device_name));
}

// Tests failure path if the filesystem setup fails.
TEST_F(DmcryptContainerTest, SetupFailedFormatExt4) {
  EXPECT_CALL(platform_, GetBlkSize(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
  EXPECT_CALL(platform_, UdevAdmSettle(_, _)).WillOnce(Return(true));
  EXPECT_CALL(platform_, FormatExt4(_, _, _)).WillOnce(Return(false));

  GenerateContainer();

  EXPECT_FALSE(container_->Setup(key_));
  // Check that the device mapper target doesn't exist.
  EXPECT_EQ(device_mapper_.GetTable(config_.dmcrypt_device_name).CryptGetKey(),
            brillo::SecureBlob());
}

// Tests the failure path on setting new filesystem features.
TEST_F(DmcryptContainerTest, SetupFailedTune2fs) {
  EXPECT_CALL(platform_, GetBlkSize(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
  EXPECT_CALL(platform_, UdevAdmSettle(_, _)).WillOnce(Return(true));
  EXPECT_CALL(platform_, Tune2Fs(_, _)).WillOnce(Return(false));

  backing_device_->Create();
  GenerateContainer();

  EXPECT_FALSE(container_->Setup(key_));
  // Check that the device mapper target doesn't exist.
  EXPECT_EQ(device_mapper_.GetTable(config_.dmcrypt_device_name).CryptGetKey(),
            brillo::SecureBlob());
}

// Tests that teardown doesn't leave an active dm-crypt device or an attached
// backing device.
TEST_F(DmcryptContainerTest, TeardownCheck) {
  EXPECT_CALL(platform_, GetBlkSize(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
  EXPECT_CALL(platform_, UdevAdmSettle(_, _)).WillOnce(Return(true));
  EXPECT_CALL(platform_, Tune2Fs(_, _)).WillOnce(Return(true));

  backing_device_->Create();
  GenerateContainer();

  EXPECT_TRUE(container_->Setup(key_));
  // Now, attempt teardown of the device.
  EXPECT_TRUE(container_->Teardown());
  // Check that the device mapper target doesn't exist.
  EXPECT_EQ(device_mapper_.GetTable(config_.dmcrypt_device_name).CryptGetKey(),
            brillo::SecureBlob());
}

// Tests that the dmcrypt container cannot be reset if it is set up with a
// filesystem.
TEST_F(DmcryptContainerTest, ResetFileSystemContainerTest) {
  EXPECT_CALL(platform_, GetBlkSize(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
  EXPECT_CALL(platform_, UdevAdmSettle(_, _)).WillOnce(Return(true));
  EXPECT_CALL(platform_, Tune2Fs(_, _)).WillOnce(Return(true));

  backing_device_->Create();
  GenerateContainer();

  EXPECT_TRUE(container_->Setup(key_));
  // Attempt a reset of the device.
  EXPECT_FALSE(container_->Reset());

  EXPECT_TRUE(container_->Teardown());
}

// Tests that the dmcrypt container can be reset if the container only sets
// up a raw device.
TEST_F(DmcryptContainerTest, ResetRawDeviceContainerTest) {
  EXPECT_CALL(platform_, GetBlkSize(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1024 * 1024 * 1024), Return(true)));
  EXPECT_CALL(platform_, UdevAdmSettle(_, _)).WillOnce(Return(true));

  SetIsRawDevice(true);
  backing_device_->Create();
  GenerateContainer();

  EXPECT_CALL(platform_,
              DiscardDevice(base::FilePath("/dev/mapper/crypt_device")))
      .WillOnce(Return(true));

  EXPECT_TRUE(container_->Setup(key_));
  // Attempt a reset of the device.
  EXPECT_TRUE(container_->Reset());
  EXPECT_TRUE(container_->Teardown());
}

}  // namespace cryptohome
