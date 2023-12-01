// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "bootlockbox/hwsec_space_impl.h"

#include <memory>
#include <utility>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/error/tpm_error.h>
#include <libhwsec/error/tpm_retry_action.h>
#include <libhwsec/frontend/bootlockbox/mock_frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>

using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnOk;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;

namespace {

// A helper function to serialize a uint16_t.
std::string uint16_to_string(uint16_t value) {
  const char* bytes = reinterpret_cast<const char*>(&value);
  return std::string(bytes, sizeof(uint16_t));
}

}  // namespace

namespace bootlockbox {

class HwsecSpaceImplTest : public testing::Test {
 public:
  void SetUp() override {
    auto hwsec = std::make_unique<hwsec::MockBootLockboxFrontend>();
    hwsec_ptr_ = hwsec.get();
    space_utility_ = std::make_unique<HwsecSpaceImpl>(std::move(hwsec));
  }

 protected:
  hwsec::MockBootLockboxFrontend* hwsec_ptr_;
  std::unique_ptr<HwsecSpaceImpl> space_utility_;
};

TEST_F(HwsecSpaceImplTest, DefineSpaceSuccess) {
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnValue(hwsec::BootLockboxFrontend::StorageState{
          .preparable = true,
          .readable = false,
          .writable = false,
          .destroyable = true,
      }));
  EXPECT_CALL(*hwsec_ptr_, PrepareSpace(kSpaceSize))
      .WillOnce(ReturnOk<hwsec::TPMError>());

  EXPECT_EQ(space_utility_->DefineSpace(), SpaceState::kSpaceUninitialized);
}

TEST_F(HwsecSpaceImplTest, DefineSpaceAlreadyDefined) {
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnValue(hwsec::BootLockboxFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));

  EXPECT_EQ(space_utility_->DefineSpace(), SpaceState::kSpaceUninitialized);
}

TEST_F(HwsecSpaceImplTest, DefineSpaceCannotPrepare) {
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnValue(hwsec::BootLockboxFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = false,
          .destroyable = false,
      }));

  EXPECT_EQ(space_utility_->DefineSpace(), SpaceState::kSpaceError);
}

TEST_F(HwsecSpaceImplTest, DefineSpacePrepareFail) {
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnValue(hwsec::BootLockboxFrontend::StorageState{
          .preparable = true,
          .readable = false,
          .writable = false,
          .destroyable = true,
      }));
  EXPECT_CALL(*hwsec_ptr_, PrepareSpace(kSpaceSize))
      .WillOnce(ReturnError<hwsec::TPMError>("Fake error",
                                             hwsec::TPMRetryAction::kNoRetry));

  EXPECT_EQ(space_utility_->DefineSpace(), SpaceState::kSpaceUndefined);
}

TEST_F(HwsecSpaceImplTest, DefineSpacePowerWash) {
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnError<hwsec::TPMError>("Fake error",
                                             hwsec::TPMRetryAction::kNoRetry));

  EXPECT_EQ(space_utility_->DefineSpace(), SpaceState::kSpaceNeedPowerwash);
}

TEST_F(HwsecSpaceImplTest, ReadSpaceReboot) {
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnError<hwsec::TPMError>("Fake error",
                                             hwsec::TPMRetryAction::kNoRetry));

  std::string data;
  EXPECT_EQ(space_utility_->ReadSpace(&data), SpaceState::kSpaceNeedPowerwash);
}

TEST_F(HwsecSpaceImplTest, ReadSpaceLengthFail) {
  std::string nvram_data = uint16_to_string(1) /* version */ +
                           uint16_to_string(0) /* flags */ +
                           std::string(3, '\x3');
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnValue(hwsec::BootLockboxFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(*hwsec_ptr_, LoadSpace())
      .WillOnce(ReturnValue(brillo::BlobFromString(nvram_data)));

  std::string data;
  EXPECT_EQ(space_utility_->ReadSpace(&data), SpaceState::kSpaceError);
}

TEST_F(HwsecSpaceImplTest, ReadSpaceUninitializedFail) {
  std::string nvram_data = std::string(kSpaceSize, '\0');
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnValue(hwsec::BootLockboxFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(*hwsec_ptr_, LoadSpace())
      .WillOnce(ReturnValue(brillo::BlobFromString(nvram_data)));

  std::string data;
  EXPECT_EQ(space_utility_->ReadSpace(&data), SpaceState::kSpaceUninitialized);
}

TEST_F(HwsecSpaceImplTest, ReadSpaceVersionFail) {
  BootLockboxSpace space{.version = 2};
  std::string nvram_data =
      std::string(reinterpret_cast<char*>(&space), kSpaceSize);
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnValue(hwsec::BootLockboxFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(*hwsec_ptr_, LoadSpace())
      .WillOnce(ReturnValue(brillo::BlobFromString(nvram_data)));

  std::string data;
  EXPECT_EQ(space_utility_->ReadSpace(&data), SpaceState::kSpaceError);
}

TEST_F(HwsecSpaceImplTest, ReadSpaceSuccess) {
  std::string test_digest(SHA256_DIGEST_LENGTH, 'a');
  BootLockboxSpace space{
      .version = 1,
      .flags = 0,
  };
  memcpy(space.digest, test_digest.c_str(), SHA256_DIGEST_LENGTH);
  std::string nvram_data =
      std::string(reinterpret_cast<char*>(&space), kSpaceSize);
  EXPECT_CALL(*hwsec_ptr_, GetSpaceState())
      .WillOnce(ReturnValue(hwsec::BootLockboxFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(*hwsec_ptr_, LoadSpace())
      .WillOnce(ReturnValue(brillo::BlobFromString(nvram_data)));

  std::string data;
  EXPECT_EQ(space_utility_->ReadSpace(&data), SpaceState::kSpaceNormal);
  EXPECT_EQ(data, test_digest);
}

TEST_F(HwsecSpaceImplTest, WriteSpaceSuccess) {
  std::string nvram_data(SHA256_DIGEST_LENGTH, 'a');
  std::string data = uint16_to_string(1) /* version */ +
                     uint16_to_string(0) /* flags */ + nvram_data;
  EXPECT_CALL(*hwsec_ptr_, StoreSpace(brillo::BlobFromString(data)))
      .WillOnce(ReturnOk<hwsec::TPMError>());

  EXPECT_TRUE(space_utility_->WriteSpace(nvram_data));
}

TEST_F(HwsecSpaceImplTest, WriteSpaceInvalidLength) {
  std::string nvram_data = "data of invalid length";
  EXPECT_CALL(*hwsec_ptr_, StoreSpace(_)).Times(0);

  EXPECT_FALSE(space_utility_->WriteSpace(nvram_data));
}

TEST_F(HwsecSpaceImplTest, LockSpace) {
  EXPECT_CALL(*hwsec_ptr_, LockSpace()).WillOnce(ReturnOk<hwsec::TPMError>());

  EXPECT_TRUE(space_utility_->LockSpace());
}

TEST_F(HwsecSpaceImplTest, LockSpaceFail) {
  EXPECT_CALL(*hwsec_ptr_, LockSpace())
      .WillOnce(ReturnError<hwsec::TPMError>("Fake error",
                                             hwsec::TPMRetryAction::kNoRetry));

  EXPECT_FALSE(space_utility_->LockSpace());
}
}  // namespace bootlockbox
