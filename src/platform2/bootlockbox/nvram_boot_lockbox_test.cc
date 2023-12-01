// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootlockbox/nvram_boot_lockbox.h"

#include <memory>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "bootlockbox/fake_hwsec_space.h"
#include "bootlockbox/proto_bindings/boot_lockbox_rpc.pb.h"

namespace {
const char kTestFilePath[] = "test_file_path.pb";
}

namespace bootlockbox {

class NVRamBootLockboxTest : public testing::Test {
 public:
  void SetUp() override {
    base::ScopedTempDir temp_directory;
    ASSERT_TRUE(temp_directory.CreateUniqueTempDir());
    file_path_ = temp_directory.GetPath().Append(kTestFilePath);
    nvram_boot_lockbox_ =
        std::make_unique<NVRamBootLockbox>(&fake_hwsec_space_, file_path_);
  }

 protected:
  FakeTpmSpace fake_hwsec_space_;
  std::unique_ptr<NVRamBootLockbox> nvram_boot_lockbox_;
  base::FilePath file_path_;
};

TEST_F(NVRamBootLockboxTest, Finalize) {
  EXPECT_TRUE(nvram_boot_lockbox_->Finalize());
  EXPECT_EQ(nvram_boot_lockbox_->GetState(), SpaceState::kSpaceWriteLocked);
}

TEST_F(NVRamBootLockboxTest, DefineSpace) {
  nvram_boot_lockbox_->SetState(SpaceState::kSpaceUndefined);
  EXPECT_TRUE(nvram_boot_lockbox_->DefineSpace());
  EXPECT_EQ(nvram_boot_lockbox_->GetState(), SpaceState::kSpaceUninitialized);
}

TEST_F(NVRamBootLockboxTest, StoreFail) {
  std::string key = "test_key";
  std::string value = "test_value";
  BootLockboxErrorCode error;
  EXPECT_TRUE(nvram_boot_lockbox_->Finalize());
  EXPECT_FALSE(nvram_boot_lockbox_->Store(key, value, &error));
  EXPECT_EQ(error, BootLockboxErrorCode::BOOTLOCKBOX_ERROR_WRITE_LOCKED);
}

TEST_F(NVRamBootLockboxTest, LoadFailDigestMisMatch) {
  std::string key = "test_key";
  std::string value = "test_value";
  BootLockboxErrorCode error;
  // avoid early failure.
  nvram_boot_lockbox_->SetState(SpaceState::kSpaceNormal);
  EXPECT_TRUE(nvram_boot_lockbox_->Store(key, value, &error));
  // modify the proto file.
  std::string invalid_proto = "aaa";
  base::WriteFile(file_path_, invalid_proto.c_str(), invalid_proto.size());
  EXPECT_FALSE(nvram_boot_lockbox_->Load());
}

TEST_F(NVRamBootLockboxTest, StoreLoadReadSuccess) {
  std::string key = "test_key";
  std::string value = "test_value_digest";
  BootLockboxErrorCode error;
  nvram_boot_lockbox_->SetState(SpaceState::kSpaceNormal);
  EXPECT_TRUE(nvram_boot_lockbox_->Store(key, value, &error));
  EXPECT_TRUE(nvram_boot_lockbox_->Load());
  std::string stored_value;
  EXPECT_TRUE(nvram_boot_lockbox_->Read(key, &stored_value, &error));
  EXPECT_EQ(value, stored_value);
  EXPECT_FALSE(
      nvram_boot_lockbox_->Read("non-exist-key", &stored_value, &error));
  EXPECT_EQ(error, BootLockboxErrorCode::BOOTLOCKBOX_ERROR_MISSING_KEY);
}

// This test simulates the situation that the device is powerwashed.
TEST_F(NVRamBootLockboxTest, FirstStoreReadSuccess) {
  std::string key = "test_key";
  std::string value = "test_value_digest";
  BootLockboxErrorCode error;
  nvram_boot_lockbox_->SetState(SpaceState::kSpaceUninitialized);
  EXPECT_TRUE(nvram_boot_lockbox_->Store(key, value, &error));
  EXPECT_EQ(error, BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NOT_SET);
  std::string stored_value;
  EXPECT_TRUE(nvram_boot_lockbox_->Read(key, &stored_value, &error));
  EXPECT_EQ(error, BootLockboxErrorCode::BOOTLOCKBOX_ERROR_NOT_SET);
  EXPECT_EQ(value, stored_value);
  EXPECT_FALSE(
      nvram_boot_lockbox_->Read("non-exist-key", &stored_value, &error));
  EXPECT_EQ(error, BootLockboxErrorCode::BOOTLOCKBOX_ERROR_MISSING_KEY);
}

}  // namespace bootlockbox
