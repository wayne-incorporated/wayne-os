// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Unit tests for FirmwareManagementParameters.

#include "cryptohome/firmware_management_parameters.h"

#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/process/process_mock.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/crc.h"
#include "cryptohome/mock_firmware_management_parameters.h"
#include "cryptohome/mock_platform.h"

namespace cryptohome {
using brillo::SecureBlob;
using ::hwsec::TPMError;
using ::hwsec::TPMErrorBase;
using ::hwsec::TPMRetryAction;
using ::hwsec_foundation::error::testing::ReturnError;
using ::hwsec_foundation::error::testing::ReturnOk;
using ::hwsec_foundation::error::testing::ReturnValue;
using ::testing::_;
using ::testing::DoAll;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;

// Provides a test fixture for ensuring Firmware Management Parameters
// flows work as expected.
//
// Multiple helpers are included to ensure tests are starting from the same
// baseline for difference scenarios, such as first boot or all-other-normal
// boots.
template <hwsec::Space fwmp_type>
class FirmwareManagementParametersTestBase : public ::testing::Test {
 public:
  FirmwareManagementParametersTestBase() : fwmp_(fwmp_type, &hwsec_) {}
  FirmwareManagementParametersTestBase(
      const FirmwareManagementParametersTestBase&) = delete;
  FirmwareManagementParametersTestBase& operator=(
      const FirmwareManagementParametersTestBase&) = delete;

  virtual ~FirmwareManagementParametersTestBase() {}

  virtual void SetUp() {
    // Create the OOBE data to reuse for post-boot tests.
    fwmp_flags_ = 0x1234;
    fwmp_hash_.assign(kHashData, kHashData + strlen(kHashData));
    fwmp_hash_ptr_ = &fwmp_hash_;
  }

  // Sets the expectations for `FirmwareManagementParameters::Store()` according
  // to the configurations.
  void SetExpectationForStore(SecureBlob* nvram_data) {
    EXPECT_CALL(hwsec_, GetSpaceState(_))
        .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
            .preparable = false,
            .readable = true,
            .writable = true,
            .destroyable = false,
        }));

    // Save blob that was written
    EXPECT_CALL(hwsec_, StoreSpace(_, _))
        .WillOnce([nvram_data](auto&&, const brillo::Blob& blob) {
          *nvram_data = SecureBlob(blob.begin(), blob.end());
          return hwsec::OkStatus();
        });
  }

  const char* kHashData = "AxxxxxxxBxxxxxxxCxxxxxxxDxxxxxxE";
  const brillo::SecureBlob kContentsWithHash = {
      // clang-format off
    0xd2,
    0x28,
    0x10,
    0x00,
    0x34, 0x12, 0x00, 0x00,
    'A', 'x', 'x', 'x', 'x', 'x', 'x', 'x',
    'B', 'x', 'x', 'x', 'x', 'x', 'x', 'x',
    'C', 'x', 'x', 'x', 'x', 'x', 'x', 'x',
    'D', 'x', 'x', 'x', 'x', 'x', 'x', 'E'
      // clang-format on
  };
  const brillo::SecureBlob kContentsNoHash = {
      // clang-format off
    0x6c,
    0x28,
    0x10,
    0x00,
    0x34, 0x12, 0x00, 0x00,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
      // clang-format on
  };
  FirmwareManagementParameters fwmp_;
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  uint32_t fwmp_flags_;
  brillo::Blob fwmp_hash_;
  brillo::Blob* fwmp_hash_ptr_;
};

class FirmwareManagementParametersTest
    : public FirmwareManagementParametersTestBase<
          hwsec::Space::kFirmwareManagementParameters> {};

// Create a new space
TEST_F(FirmwareManagementParametersTest, CreateNew) {
  // Prepare the new space
  EXPECT_CALL(hwsec_, PrepareSpace(hwsec::Space::kFirmwareManagementParameters,
                                   FirmwareManagementParameters::kNvramBytes))
      .WillOnce(ReturnOk<TPMErrorBase>());

  EXPECT_TRUE(fwmp_.Create());
}

// Create failure
TEST_F(FirmwareManagementParametersTest, CreateFailure) {
  // Prepare the space failed
  EXPECT_CALL(hwsec_, PrepareSpace(hwsec::Space::kFirmwareManagementParameters,
                                   FirmwareManagementParameters::kNvramBytes))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  EXPECT_FALSE(fwmp_.Create());
}

// Destroy existing space
TEST_F(FirmwareManagementParametersTest, Destroy) {
  // Destroy the space
  EXPECT_CALL(hwsec_, DestroySpace(hwsec::Space::kFirmwareManagementParameters))
      .WillOnce(ReturnOk<TPMErrorBase>());

  EXPECT_TRUE(fwmp_.Destroy());
}

// Destroy failure
TEST_F(FirmwareManagementParametersTest, DestroyFailure) {
  // Destroy the space failed
  EXPECT_CALL(hwsec_, DestroySpace(hwsec::Space::kFirmwareManagementParameters))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  EXPECT_FALSE(fwmp_.Destroy());
}

// Store flags and hash
TEST_F(FirmwareManagementParametersTest, StoreFlagsAndHash) {
  SecureBlob nvram_data;
  SetExpectationForStore(&nvram_data);
  EXPECT_TRUE(fwmp_.Store(fwmp_flags_, fwmp_hash_ptr_));
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(nvram_data, kContentsWithHash);
}

// Store flags only
TEST_F(FirmwareManagementParametersTest, StoreFlagsOnly) {
  SecureBlob nvram_data;
  fwmp_hash_ptr_ = NULL;
  SetExpectationForStore(&nvram_data);
  EXPECT_TRUE(fwmp_.Store(fwmp_flags_, fwmp_hash_ptr_));
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(nvram_data, kContentsNoHash);
}

// Store fails if hash is wrong size
TEST_F(FirmwareManagementParametersTest, StoreHashSizeBad) {
  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));

  // Return a bad NVRAM size.
  brillo::Blob bad_hash = brillo::BlobFromString("wrong-size");
  EXPECT_FALSE(fwmp_.Store(fwmp_flags_, &bad_hash));
  EXPECT_FALSE(fwmp_.IsLoaded());
}

// Store failure
TEST_F(FirmwareManagementParametersTest, StoreFailure) {
  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, StoreSpace(_, _))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  // Return a bad NVRAM size.
  EXPECT_FALSE(fwmp_.Store(fwmp_flags_, fwmp_hash_ptr_));
  EXPECT_FALSE(fwmp_.IsLoaded());
}

// Load existing data
TEST_F(FirmwareManagementParametersTest, LoadExisting) {
  uint32_t flags;
  brillo::Blob hash;
  SecureBlob nvram_data(kContentsWithHash);

  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, LoadSpace(_))
      .WillOnce(
          ReturnValue(brillo::Blob(nvram_data.begin(), nvram_data.end())));

  // Load succeeds
  EXPECT_FALSE(fwmp_.IsLoaded());
  EXPECT_TRUE(fwmp_.Load());
  EXPECT_TRUE(fwmp_.IsLoaded());

  // And really loaded things
  EXPECT_TRUE(fwmp_.GetFlags(&flags));
  EXPECT_EQ(flags, fwmp_flags_);
  EXPECT_TRUE(fwmp_.GetDeveloperKeyHash(&hash));
  EXPECT_EQ(fwmp_hash_, hash);
}

// GetFlags automatically loads
TEST_F(FirmwareManagementParametersTest, GetFlags) {
  uint32_t flags;
  brillo::Blob hash;
  SecureBlob nvram_data(kContentsWithHash);

  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, LoadSpace(_))
      .WillOnce(
          ReturnValue(brillo::Blob(nvram_data.begin(), nvram_data.end())));

  EXPECT_FALSE(fwmp_.IsLoaded());
  EXPECT_TRUE(fwmp_.GetFlags(&flags));
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(flags, fwmp_flags_);
}

// GetDeveloperKeyHash automatically loads
TEST_F(FirmwareManagementParametersTest, GetDeveloperKeyHash) {
  brillo::Blob hash;
  SecureBlob nvram_data(kContentsWithHash);

  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, LoadSpace(_))
      .WillOnce(
          ReturnValue(brillo::Blob(nvram_data.begin(), nvram_data.end())));

  EXPECT_FALSE(fwmp_.IsLoaded());
  EXPECT_TRUE(fwmp_.GetDeveloperKeyHash(&hash));
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(fwmp_hash_, hash);
}

// Load and Get fail if space doesn't exist
TEST_F(FirmwareManagementParametersTest, LoadNoNvram) {
  uint32_t flags;
  brillo::Blob hash;

  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .Times(3)
      .WillRepeatedly(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  EXPECT_FALSE(fwmp_.Load());
  EXPECT_FALSE(fwmp_.IsLoaded());

  EXPECT_FALSE(fwmp_.GetFlags(&flags));
  EXPECT_FALSE(fwmp_.IsLoaded());

  EXPECT_FALSE(fwmp_.GetDeveloperKeyHash(&hash));
  EXPECT_FALSE(fwmp_.IsLoaded());
}

// Load fails on read error
TEST_F(FirmwareManagementParametersTest, LoadReadError) {
  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, LoadSpace(_))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  EXPECT_FALSE(fwmp_.Load());
}

// Load fails on space too small
TEST_F(FirmwareManagementParametersTest, LoadNvramTooSmall) {
  SecureBlob nvram_data(kContentsWithHash);

  nvram_data.erase(nvram_data.begin(), nvram_data.begin() + 1);

  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, LoadSpace(_))
      .WillOnce(
          ReturnValue(brillo::Blob(nvram_data.begin(), nvram_data.end())));

  EXPECT_FALSE(fwmp_.Load());
}

// Load fails on bad struct size
TEST_F(FirmwareManagementParametersTest, LoadBadStructSize) {
  SecureBlob nvram_data(kContentsWithHash);

  // Alter struct size
  nvram_data[1]++;

  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, LoadSpace(_))
      .WillOnce(
          ReturnValue(brillo::Blob(nvram_data.begin(), nvram_data.end())));

  EXPECT_FALSE(fwmp_.Load());
}

// Load fails on bad CRC
TEST_F(FirmwareManagementParametersTest, LoadBadCrc) {
  SecureBlob nvram_data(kContentsWithHash);

  // Alter CRC
  nvram_data[0] ^= 0x42;

  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, LoadSpace(_))
      .WillOnce(
          ReturnValue(brillo::Blob(nvram_data.begin(), nvram_data.end())));

  EXPECT_FALSE(fwmp_.Load());
}

// Load allows different minor version
TEST_F(FirmwareManagementParametersTest, LoadMinorVersion) {
  SecureBlob nvram_data(kContentsWithHash);

  // Alter minor version
  nvram_data[2] += 1;

  // Recalculate CRC
  nvram_data[0] =
      Crc8(nvram_data.data() + FirmwareManagementParameters::kCrcDataOffset,
           nvram_data.size() - FirmwareManagementParameters::kCrcDataOffset);

  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, LoadSpace(_))
      .WillOnce(
          ReturnValue(brillo::Blob(nvram_data.begin(), nvram_data.end())));

  EXPECT_TRUE(fwmp_.Load());
}

// Load fails on different major version
TEST_F(FirmwareManagementParametersTest, LoadMajorVersion) {
  SecureBlob nvram_data(kContentsWithHash);

  // Alter major version
  nvram_data[2] += 0x10;

  // Recalculate CRC
  nvram_data[0] =
      Crc8(nvram_data.data() + FirmwareManagementParameters::kCrcDataOffset,
           nvram_data.size() - FirmwareManagementParameters::kCrcDataOffset);

  EXPECT_CALL(hwsec_, GetSpaceState(_))
      .WillRepeatedly(ReturnValue(hwsec::CryptohomeFrontend::StorageState{
          .preparable = false,
          .readable = true,
          .writable = true,
          .destroyable = false,
      }));
  EXPECT_CALL(hwsec_, LoadSpace(_))
      .WillOnce(
          ReturnValue(brillo::Blob(nvram_data.begin(), nvram_data.end())));

  EXPECT_FALSE(fwmp_.Load());
}

class FirmwareManagementParametersPlatformIndexTest
    : public FirmwareManagementParametersTestBase<
          hwsec::Space::kPlatformFirmwareManagementParameters> {};

// Store flags and hash
TEST_F(FirmwareManagementParametersPlatformIndexTest, StoreFlagsAndHash) {
  SecureBlob nvram_data;
  SetExpectationForStore(&nvram_data);
  EXPECT_TRUE(fwmp_.Store(fwmp_flags_, fwmp_hash_ptr_));
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(nvram_data, kContentsWithHash);
}

// Store flags only
TEST_F(FirmwareManagementParametersPlatformIndexTest, StoreFlagsOnly) {
  SecureBlob nvram_data;
  fwmp_hash_ptr_ = nullptr;
  SetExpectationForStore(&nvram_data);
  EXPECT_TRUE(fwmp_.Store(fwmp_flags_, fwmp_hash_ptr_));
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(nvram_data, kContentsNoHash);
}

TEST_F(FirmwareManagementParametersPlatformIndexTest, CreateSetsDefaultFlags) {
  SecureBlob default_nvram_data;
  SetExpectationForStore(&default_nvram_data);
  EXPECT_TRUE(fwmp_.Store(/*flags=*/0, /*developer_key_hash=*/nullptr));
  EXPECT_TRUE(fwmp_.IsLoaded());

  // Modify the content of FWMP.
  SecureBlob nvram_data;
  SetExpectationForStore(&nvram_data);
  EXPECT_TRUE(fwmp_.Store(fwmp_flags_, fwmp_hash_ptr_));
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(nvram_data, kContentsWithHash);

  // `Create()` is supposed to write the default content.
  SetExpectationForStore(&nvram_data);
  EXPECT_TRUE(fwmp_.Create());
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(nvram_data.to_string(), default_nvram_data.to_string());

  // Modify the content of FWMP again.
  SetExpectationForStore(&nvram_data);
  EXPECT_TRUE(fwmp_.Store(fwmp_flags_, fwmp_hash_ptr_));
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(nvram_data, kContentsWithHash);

  // `Destroy()` is supposed to write the default content.
  SetExpectationForStore(&nvram_data);
  EXPECT_TRUE(fwmp_.Destroy());
  EXPECT_TRUE(fwmp_.IsLoaded());
  EXPECT_EQ(nvram_data.to_string(), default_nvram_data.to_string());
}

}  // namespace cryptohome
