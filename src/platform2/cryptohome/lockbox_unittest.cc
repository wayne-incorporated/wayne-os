// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// Unit tests for Lockbox.

#include "cryptohome/lockbox.h"

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/mock_lockbox.h"
#include "cryptohome/mock_platform.h"

namespace cryptohome {
using ::brillo::SecureBlob;
using ::hwsec::TPMError;
using ::hwsec::TPMErrorBase;
using ::hwsec::TPMRetryAction;
using ::hwsec_foundation::SecureBlobToHex;
using ::hwsec_foundation::Sha256;
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

// Provides a test fixture for ensuring Lockbox-flows work as expected.
//
// Multiple helpers are included to ensure tests are starting from the same
// baseline for difference scenarios, such as first boot or all-other-normal
// boots.
class LockboxTest : public ::testing::Test {
 public:
  LockboxTest() : lockbox_(&hwsec_, hwsec::Space::kInstallAttributes) {}
  LockboxTest(const LockboxTest&) = delete;
  LockboxTest& operator=(const LockboxTest&) = delete;

  ~LockboxTest() override = default;

  void SetUp() override {
    // Create the OOBE data to reuse for post-boot tests.
    // This generates the expected NVRAM value and serialized file data.
    file_data_.assign(kFileData, kFileData + strlen(kFileData));
  }

 protected:
  static inline constexpr char kFileData[] = "42";
  Lockbox lockbox_;
  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  brillo::Blob file_data_;
};

TEST_F(LockboxTest, ResetOk) {
  EXPECT_CALL(hwsec_, PrepareSpace(hwsec::Space::kInstallAttributes,
                                   LockboxContents::kNvramSize))
      .WillOnce(ReturnOk<TPMError>());

  LockboxError error;
  EXPECT_TRUE(lockbox_.Reset(&error));
}

TEST_F(LockboxTest, ResetFailed) {
  EXPECT_CALL(hwsec_, PrepareSpace(hwsec::Space::kInstallAttributes,
                                   LockboxContents::kNvramSize))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  LockboxError error;
  EXPECT_FALSE(lockbox_.Reset(&error));
  EXPECT_EQ(error, LockboxError::kTpmError);
}

TEST_F(LockboxTest, StoreOk) {
  EXPECT_CALL(hwsec_, StoreSpace(hwsec::Space::kInstallAttributes, _))
      .WillOnce(ReturnOk<TPMError>());

  LockboxError error;
  EXPECT_TRUE(lockbox_.Store(file_data_, &error));
}

TEST_F(LockboxTest, StoreFailed) {
  EXPECT_CALL(hwsec_, StoreSpace(hwsec::Space::kInstallAttributes, _))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));

  LockboxError error;
  EXPECT_FALSE(lockbox_.Store(file_data_, &error));
  EXPECT_EQ(error, LockboxError::kTpmError);
}

class LockboxContentsTest : public testing::Test {
 public:
  LockboxContentsTest() = default;

  void GenerateNvramData(brillo::SecureBlob* nvram_data) {
    std::unique_ptr<LockboxContents> contents = LockboxContents::New();
    ASSERT_TRUE(contents);
    ASSERT_TRUE(contents->SetKeyMaterial(
        brillo::SecureBlob(contents->key_material_size(), 'A')));
    ASSERT_TRUE(contents->Protect({42}));
    ASSERT_TRUE(contents->Encode(nvram_data));
  }

  void LoadAndVerify(const brillo::SecureBlob& nvram_data,
                     const brillo::Blob& data,
                     LockboxContents::VerificationResult expected_result) {
    std::unique_ptr<LockboxContents> contents = LockboxContents::New();
    ASSERT_TRUE(contents);
    ASSERT_TRUE(contents->Decode(nvram_data));
    EXPECT_EQ(expected_result, contents->Verify(data));
  }
};

TEST_F(LockboxContentsTest, LoadAndVerifyOk) {
  brillo::SecureBlob nvram_data;
  ASSERT_NO_FATAL_FAILURE(GenerateNvramData(&nvram_data));
  LoadAndVerify(nvram_data, {42}, LockboxContents::VerificationResult::kValid);
}

TEST_F(LockboxContentsTest, LoadAndVerifyBadSize) {
  SecureBlob nvram_data;
  ASSERT_NO_FATAL_FAILURE(GenerateNvramData(&nvram_data));

  // Change the expected file size to 0.
  nvram_data[0] = 0;
  nvram_data[1] = 0;
  nvram_data[2] = 0;
  nvram_data[3] = 0;

  LoadAndVerify(nvram_data, {42},
                LockboxContents::VerificationResult::kSizeMismatch);
}

TEST_F(LockboxContentsTest, LoadAndVerifyBadHash) {
  SecureBlob nvram_data;
  ASSERT_NO_FATAL_FAILURE(GenerateNvramData(&nvram_data));

  // Invalidate the hash.
  nvram_data.back() ^= 0xff;

  LoadAndVerify(nvram_data, {42},
                LockboxContents::VerificationResult::kHashMismatch);
}

TEST_F(LockboxContentsTest, LoadAndVerifyBadData) {
  SecureBlob nvram_data;
  ASSERT_NO_FATAL_FAILURE(GenerateNvramData(&nvram_data));
  LoadAndVerify(nvram_data, {17},
                LockboxContents::VerificationResult::kHashMismatch);
}

}  // namespace cryptohome
