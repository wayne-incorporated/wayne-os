// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "libhwsec/backend/mock_backend.h"
#include "libhwsec/error/tpm_retry_action.h"
#include "libhwsec/factory/tpm2_simulator_factory_for_test.h"
#include "libhwsec/frontend/oobe_config/encrypted_data.pb.h"
#include "libhwsec/frontend/oobe_config/frontend_impl.h"
#include "libhwsec/structures/key.h"
#include "libhwsec/structures/permission.h"

using brillo::BlobFromString;
using hwsec_foundation::Sha256;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::NotOkAnd;
using hwsec_foundation::error::testing::NotOkWith;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::DoAll;
using testing::Eq;
using testing::Mock;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
namespace hwsec {

namespace {
constexpr uint32_t kRollbackSpaceSize = 32;
constexpr uint32_t kEnterpriseRollbackIndex = 0x100e;
constexpr uint32_t kBootModePcr = 0;
constexpr char kWrongPcrValue[] = "wrong_pcr_value";

MATCHER_P(RetryAction, matcher, "") {
  if (arg.ok()) {
    return false;
  }
  return ExplainMatchResult(matcher, arg->ToTPMRetryAction(), result_listener);
}

}  // namespace

class OobeConfigFrontendImplTpm2SimTest : public testing::Test {
 public:
  void SetUp() override {
    hwsec_oobe_config_ = hwsec_factory_.GetOobeConfigFrontend();
  }

 protected:
  hwsec::Tpm2SimulatorFactoryForTest hwsec_factory_;
  std::unique_ptr<const OobeConfigFrontend> hwsec_oobe_config_;
};

TEST_F(OobeConfigFrontendImplTpm2SimTest, RollbackSpaceNotReady) {
  EXPECT_THAT(hwsec_oobe_config_->IsRollbackSpaceReady(),
              NotOkAnd(RetryAction(Eq(TPMRetryAction::kSpaceNotFound))));
}

TEST_F(OobeConfigFrontendImplTpm2SimTest, RollbackSpaceReady) {
  EXPECT_TRUE(hwsec_factory_.GetFakeTpmNvramForTest().DefinePlatformCreateSpace(
      kEnterpriseRollbackIndex, kRollbackSpaceSize));
  EXPECT_THAT(hwsec_oobe_config_->IsRollbackSpaceReady(), IsOk());
}

TEST_F(OobeConfigFrontendImplTpm2SimTest, EncryptAndDecrypt) {
  EXPECT_TRUE(hwsec_factory_.GetFakeTpmNvramForTest().DefinePlatformCreateSpace(
      kEnterpriseRollbackIndex, kRollbackSpaceSize));

  brillo::SecureBlob plain_data("plain_data");
  auto ecnrypted = hwsec_oobe_config_->Encrypt(plain_data);

  ASSERT_OK(ecnrypted);

  auto decrypted = hwsec_oobe_config_->Decrypt(ecnrypted.value());

  EXPECT_THAT(decrypted, IsOkAndHolds(plain_data));
}

TEST_F(OobeConfigFrontendImplTpm2SimTest, EncryptAndDecryptFailWithWrongPcr) {
  EXPECT_TRUE(hwsec_factory_.GetFakeTpmNvramForTest().DefinePlatformCreateSpace(
      kEnterpriseRollbackIndex, kRollbackSpaceSize));

  brillo::SecureBlob plain_data("plain_data");
  auto ecnrypted = hwsec_oobe_config_->Encrypt(plain_data);

  ASSERT_OK(ecnrypted);

  EXPECT_TRUE(hwsec_factory_.ExtendPCR(kBootModePcr, kWrongPcrValue));

  auto decrypted = hwsec_oobe_config_->Decrypt(ecnrypted.value());

  EXPECT_THAT(decrypted, NotOkWith("Failed to decrypt the data"));
}

TEST_F(OobeConfigFrontendImplTpm2SimTest, EncryptAndDecryptFailWithResetSpace) {
  EXPECT_TRUE(hwsec_factory_.GetFakeTpmNvramForTest().DefinePlatformCreateSpace(
      kEnterpriseRollbackIndex, kRollbackSpaceSize));

  brillo::SecureBlob plain_data("plain_data");
  auto ecnrypted = hwsec_oobe_config_->Encrypt(plain_data);

  ASSERT_OK(ecnrypted);

  EXPECT_THAT(hwsec_oobe_config_->ResetRollbackSpace(), IsOk());

  auto decrypted = hwsec_oobe_config_->Decrypt(ecnrypted.value());

  EXPECT_THAT(decrypted, NotOkWith("Failed to decrypt the data"));
}

TEST_F(OobeConfigFrontendImplTpm2SimTest,
       EncryptAndDecryptFailWithWrongVersion) {
  EXPECT_TRUE(hwsec_factory_.GetFakeTpmNvramForTest().DefinePlatformCreateSpace(
      kEnterpriseRollbackIndex, kRollbackSpaceSize));

  brillo::SecureBlob plain_data("plain_data");
  auto ecnrypted = hwsec_oobe_config_->Encrypt(plain_data);

  ASSERT_OK(ecnrypted);

  EXPECT_THAT(hwsec_oobe_config_->ResetRollbackSpace(), IsOk());

  OobeConfigEncryptedData data;
  EXPECT_TRUE(data.ParseFromString(brillo::BlobToString(ecnrypted.value())));
  data.set_version(1234);

  auto decrypted = hwsec_oobe_config_->Decrypt(
      brillo::BlobFromString(data.SerializeAsString()));

  EXPECT_THAT(decrypted, NotOkWith("Unsupported encrypted data version"));
}

TEST_F(OobeConfigFrontendImplTpm2SimTest, DecryptFailWithWrongFormatBlob) {
  brillo::Blob wrong_blob = brillo::BlobFromString("wrong_blob_content");

  auto decrypted = hwsec_oobe_config_->Decrypt(wrong_blob);

  EXPECT_THAT(decrypted, NotOkWith("Failed to parse the encrypted data"));
}

TEST_F(OobeConfigFrontendImplTpm2SimTest, EncryptFailWithNoSpace) {
  brillo::SecureBlob plain_data("plain_data");
  auto ecnrypted = hwsec_oobe_config_->Encrypt(plain_data);

  EXPECT_THAT(ecnrypted,
              NotOkWith("Failed to store enterprise rollback space"));
}

TEST_F(OobeConfigFrontendImplTpm2SimTest, EncryptFailWithRandomFailure) {
  EXPECT_TRUE(hwsec_factory_.GetFakeTpmNvramForTest().DefinePlatformCreateSpace(
      kEnterpriseRollbackIndex, kRollbackSpaceSize));

  EXPECT_CALL(hwsec_factory_.GetMockBackend().GetMock().random,
              RandomSecureBlob(_))
      .WillOnce(ReturnError<TPMError>("RNG failure", TPMRetryAction::kNoRetry));

  brillo::SecureBlob plain_data("plain_data");
  auto ecnrypted = hwsec_oobe_config_->Encrypt(plain_data);

  EXPECT_THAT(ecnrypted, NotOkWith("Failed to generate random"));
}

}  // namespace hwsec
