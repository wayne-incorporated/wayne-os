// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/encrypted_container/loopback_device.h"

#include <memory>
#include <optional>

#include <base/files/file_path.h>
#include <base/values.h>
#include <gtest/gtest.h>

#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/encrypted_container/backing_device.h"

namespace cryptohome {

class LoopbackDeviceTest : public ::testing::Test {
 public:
  LoopbackDeviceTest()
      : config_(
            {.type = BackingDeviceType::kLoopbackDevice,
             .name = "foo",
             .size = 1024 * 1024 * 1024,
             .loopback = {.backing_file_path = base::FilePath("/a.block")}}),
        backing_device_(std::make_unique<LoopbackDevice>(config_, &platform_)) {
  }
  ~LoopbackDeviceTest() override = default;

 protected:
  BackingDeviceConfig config_;
  MockPlatform platform_;
  std::unique_ptr<LoopbackDevice> backing_device_;
};

// Tests the successful creation of the loop device's backing sparse file.
TEST_F(LoopbackDeviceTest, LoopbackDeviceCreate) {
  EXPECT_TRUE(backing_device_->Create());

  // Check that the sparse file was created with the correct mode.
  EXPECT_TRUE(backing_device_->Exists());
  mode_t mode;
  ASSERT_TRUE(
      platform_.GetPermissions(config_.loopback.backing_file_path, &mode));
  EXPECT_EQ(mode, S_IRUSR | S_IWUSR);
}

// Tests purge of the backing sparse file.
TEST_F(LoopbackDeviceTest, LoopbackPurge) {
  EXPECT_TRUE(platform_.WriteFile(config_.loopback.backing_file_path,
                                  brillo::Blob(32, 0)));
  EXPECT_TRUE(backing_device_->Purge());
  EXPECT_FALSE(backing_device_->Exists());
}

// Tests setup for a loopback device succeeded.
TEST_F(LoopbackDeviceTest, LoopbackSetup) {
  EXPECT_TRUE(backing_device_->Setup());

  EXPECT_NE(backing_device_->GetPath(), std::nullopt);
  EXPECT_TRUE(backing_device_->Teardown());
}

// Tests teardown of a loopback device doesn't leave the loop device attached.
TEST_F(LoopbackDeviceTest, ValidLoopbackDeviceTeardown) {
  EXPECT_TRUE(backing_device_->Setup());
  EXPECT_TRUE(backing_device_->Teardown());

  EXPECT_EQ(backing_device_->GetPath(), std::nullopt);
}

// Test creating and purging of a fixed loopback device does not succeed.
TEST_F(LoopbackDeviceTest, FixedLoopbackWontCreateOrPurge) {
  // Ensure the backing file already exists.
  EXPECT_TRUE(backing_device_->Create());
  // Set up a new loopback device with the same config plus the fixed option.
  BackingDeviceConfig fixed_config = config_;
  fixed_config.loopback.fixed_backing = true;
  std::unique_ptr<LoopbackDevice> loop =
      std::make_unique<LoopbackDevice>(fixed_config, &platform_);

  // Ensure the backing device already exists so the the failure can only be due
  // to it being fixed.
  EXPECT_TRUE(loop->Exists());
  // Create should not succeed on a fixed device.
  EXPECT_FALSE(loop->Create());
  // Purge should not succeed on a fixed device.
  EXPECT_FALSE(loop->Purge());
  // Setup and teardown, however, should still work fine.
  EXPECT_TRUE(loop->Setup());
  EXPECT_TRUE(loop->Teardown());
}
}  // namespace cryptohome
