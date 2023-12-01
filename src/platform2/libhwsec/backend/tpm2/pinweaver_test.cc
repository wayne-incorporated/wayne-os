// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <trunks/error_codes.h>
#include <trunks/mock_tpm_utility.h>

#define __packed __attribute((packed))
#define __aligned(x) __attribute((aligned(x)))
#include <pinweaver/pinweaver_types.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"

using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::DoAll;
using testing::Eq;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using tpm_manager::TpmManagerStatus;
using ErrorCode = hwsec::Backend::PinWeaver::CredentialTreeResult::ErrorCode;

namespace hwsec {

using BackendPinweaverTpm2Test = BackendTpm2TestBase;

TEST_F(BackendPinweaverTpm2Test, IsEnabled) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().IsEnabled(), IsOkAndHolds(true));
}

TEST_F(BackendPinweaverTpm2Test, IsEnabledMismatch) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(Return(trunks::SAPI_RC_ABI_MISMATCH))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().IsEnabled(), IsOkAndHolds(true));
}

TEST_F(BackendPinweaverTpm2Test, IsDisabled) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().IsEnabled(), IsOkAndHolds(false));
}

TEST_F(BackendPinweaverTpm2Test, IsDisabledMismatch) {
  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(Return(trunks::SAPI_RC_ABI_MISMATCH))
      .WillOnce(Return(trunks::SAPI_RC_ABI_MISMATCH));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().IsEnabled(), IsOkAndHolds(false));
}

TEST_F(BackendPinweaverTpm2Test, Reset) {
  constexpr uint32_t kLengthLabels = 14;
  constexpr uint32_t kBitsPerLevel = 2;
  constexpr uint32_t kVersion = 1;
  const std::string kFakeRoot = "fake_root";
  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverResetTree(kVersion, 2, 7, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(0), SetArgPointee<4>(kFakeRoot),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result =
      backend_->GetPinWeaverTpm2().Reset(kBitsPerLevel, kLengthLabels);

  ASSERT_OK(result);
  EXPECT_EQ(result->error, ErrorCode::kSuccess);
  EXPECT_EQ(result->new_root, brillo::BlobFromString(kFakeRoot));
}

TEST_F(BackendPinweaverTpm2Test, ResetFailure) {
  constexpr uint32_t kLengthLabels = 128;
  constexpr uint32_t kBitsPerLevel = 128;
  constexpr uint32_t kVersion = 1;
  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverResetTree(kVersion, 128, 1, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(PW_ERR_BITS_PER_LEVEL_INVALID),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result =
      backend_->GetPinWeaverTpm2().Reset(kBitsPerLevel, kLengthLabels);

  ASSERT_NOT_OK(result);
}

TEST_F(BackendPinweaverTpm2Test, InsertCredential) {
  constexpr uint32_t kVersion = 2;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeLeSecret("fake_le_secret");
  const brillo::SecureBlob kFakeHeSecret("fake_he_secret");
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const hwsec::Backend::PinWeaver::DelaySchedule kDelaySched = {
      {5, UINT32_MAX},
  };
  const uint32_t kExpirationDelay = 100;
  const std::vector<OperationPolicySetting> kPolicies = {
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = std::nullopt,
                      },
              },
      },
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = "fake_username",
                      },
              },
      },
  };
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverInsertLeaf(kVersion, kLabel, _, kFakeLeSecret,
                                  kFakeHeSecret, kFakeResetSecret, kDelaySched,
                                  _, Eq(kExpirationDelay), _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<9>(0), SetArgPointee<10>(kFakeRoot),
                      SetArgPointee<11>(kFakeCred), SetArgPointee<12>(kFakeMac),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().InsertCredential(
      kPolicies, kLabel, kHAux, kFakeLeSecret, kFakeHeSecret, kFakeResetSecret,
      kDelaySched, kExpirationDelay);

  ASSERT_OK(result);
  EXPECT_EQ(result->error, ErrorCode::kSuccess);
  EXPECT_EQ(result->new_root, brillo::BlobFromString(kFakeRoot));
  ASSERT_TRUE(result->new_cred_metadata.has_value());
  EXPECT_EQ(result->new_cred_metadata.value(),
            brillo::BlobFromString(kFakeCred));
  ASSERT_TRUE(result->new_mac.has_value());
  EXPECT_EQ(result->new_mac.value(), brillo::BlobFromString(kFakeMac));
}

TEST_F(BackendPinweaverTpm2Test, InsertCredentialUnsupportedPolicy) {
  constexpr uint32_t kVersion = 2;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeLeSecret("fake_le_secret");
  const brillo::SecureBlob kFakeHeSecret("fake_he_secret");
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const hwsec::Backend::PinWeaver::DelaySchedule kDelaySched = {
      {5, UINT32_MAX},
  };
  const uint32_t kExpirationDelay = 100;
  const std::vector<OperationPolicySetting> kPolicies = {
      OperationPolicySetting{.permission =
                                 Permission{
                                     .auth_value = brillo::SecureBlob("auth"),
                                 }},
  };
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().InsertCredential(
      kPolicies, kLabel, kHAux, kFakeLeSecret, kFakeHeSecret, kFakeResetSecret,
      kDelaySched, kExpirationDelay);

  EXPECT_FALSE(result.ok());
}

TEST_F(BackendPinweaverTpm2Test, InsertCredentialV0PolicyUnsupported) {
  constexpr uint32_t kVersion = 0;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeLeSecret("fake_le_secret");
  const brillo::SecureBlob kFakeHeSecret("fake_he_secret");
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const hwsec::Backend::PinWeaver::DelaySchedule kDelaySched = {
      {5, UINT32_MAX},
  };
  const std::vector<OperationPolicySetting> kPolicies = {
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = std::nullopt,
                      },
              },
      },
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = "fake_username",
                      },
              },
      },
  };
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().InsertCredential(
      kPolicies, kLabel, kHAux, kFakeLeSecret, kFakeHeSecret, kFakeResetSecret,
      kDelaySched, /*expiration_delay=*/std::nullopt);

  EXPECT_FALSE(result.ok());
}

TEST_F(BackendPinweaverTpm2Test, InsertCredentialV1ExpirationUnsupported) {
  constexpr uint32_t kVersion = 1;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeLeSecret("fake_le_secret");
  const brillo::SecureBlob kFakeHeSecret("fake_he_secret");
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const hwsec::Backend::PinWeaver::DelaySchedule kDelaySched = {
      {5, UINT32_MAX},
  };
  const uint32_t kExpirationDelay = 100;
  const std::vector<OperationPolicySetting> kPolicies = {
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = std::nullopt,
                      },
              },
      },
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = "fake_username",
                      },
              },
      },
  };
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().InsertCredential(
      kPolicies, kLabel, kHAux, kFakeLeSecret, kFakeHeSecret, kFakeResetSecret,
      kDelaySched, kExpirationDelay);

  EXPECT_FALSE(result.ok());
}

TEST_F(BackendPinweaverTpm2Test, InsertCredentialNoDelay) {
  constexpr uint32_t kVersion = 2;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeLeSecret("fake_le_secret");
  const brillo::SecureBlob kFakeHeSecret("fake_he_secret");
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const hwsec::Backend::PinWeaver::DelaySchedule kDelaySched = {
      {5, UINT32_MAX},
  };
  const uint32_t kExpirationDelay = 100;
  const std::vector<OperationPolicySetting> kPolicies = {
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = std::nullopt,
                      },
              },
      },
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = "fake_username",
                      },
              },
      },
  };
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverInsertLeaf(kVersion, kLabel, _, kFakeLeSecret,
                                  kFakeHeSecret, kFakeResetSecret, kDelaySched,
                                  _, Eq(kExpirationDelay), _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<9>(PW_ERR_DELAY_SCHEDULE_INVALID),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().InsertCredential(
      kPolicies, kLabel, kHAux, kFakeLeSecret, kFakeHeSecret, kFakeResetSecret,
      kDelaySched, kExpirationDelay);

  EXPECT_FALSE(result.ok());
}

TEST_F(BackendPinweaverTpm2Test, CheckCredential) {
  constexpr uint32_t kVersion = 1;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeLeSecret("fake_le_secret");
  const brillo::SecureBlob kFakeHeSecret("fake_he_secret");
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverTryAuth(kVersion, kFakeLeSecret, _, kFakeCred, _, _, _,
                               _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(0), SetArgPointee<5>(kFakeRoot),
                      SetArgPointee<7>(kFakeHeSecret),
                      SetArgPointee<8>(kFakeResetSecret),
                      SetArgPointee<9>(kNewCred), SetArgPointee<10>(kFakeMac),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().CheckCredential(
      kLabel, kHAux, brillo::BlobFromString(kFakeCred), kFakeLeSecret);

  ASSERT_OK(result);
  EXPECT_EQ(result->error, ErrorCode::kSuccess);
  EXPECT_EQ(result->new_root, brillo::BlobFromString(kFakeRoot));
  ASSERT_TRUE(result->new_cred_metadata.has_value());
  EXPECT_EQ(result->new_cred_metadata.value(),
            brillo::BlobFromString(kNewCred));
  ASSERT_TRUE(result->new_mac.has_value());
  EXPECT_EQ(result->new_mac.value(), brillo::BlobFromString(kFakeMac));
  ASSERT_TRUE(result->he_secret.has_value());
  EXPECT_EQ(result->he_secret.value(), kFakeHeSecret);
  ASSERT_TRUE(result->reset_secret.has_value());
  EXPECT_EQ(result->reset_secret.value(), kFakeResetSecret);
}

TEST_F(BackendPinweaverTpm2Test, CheckCredentialAuthFail) {
  constexpr uint32_t kVersion = 1;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeLeSecret("fake_le_secret");
  const brillo::SecureBlob kFakeHeSecret("fake_he_secret");
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverTryAuth(kVersion, kFakeLeSecret, _, kFakeCred, _, _, _,
                               _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(PW_ERR_LOWENT_AUTH_FAILED),
                      SetArgPointee<5>(kFakeRoot), SetArgPointee<9>(kNewCred),
                      SetArgPointee<10>(kFakeMac),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().CheckCredential(
      kLabel, kHAux, brillo::BlobFromString(kFakeCred), kFakeLeSecret);

  ASSERT_OK(result);
  EXPECT_EQ(result->error, ErrorCode::kInvalidLeSecret);
  EXPECT_EQ(result->new_root, brillo::BlobFromString(kFakeRoot));
  ASSERT_TRUE(result->new_cred_metadata.has_value());
  EXPECT_EQ(result->new_cred_metadata.value(),
            brillo::BlobFromString(kNewCred));
  ASSERT_TRUE(result->new_mac.has_value());
  EXPECT_EQ(result->new_mac.value(), brillo::BlobFromString(kFakeMac));
  ASSERT_TRUE(result->he_secret.has_value());
  EXPECT_TRUE(result->he_secret->empty());
  ASSERT_TRUE(result->reset_secret.has_value());
  EXPECT_TRUE(result->reset_secret->empty());
}

TEST_F(BackendPinweaverTpm2Test, CheckCredentialTpmFail) {
  constexpr uint32_t kVersion = 1;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeCred = "fake_cred";
  const brillo::SecureBlob kFakeLeSecret("fake_le_secret");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverTryAuth(kVersion, kFakeLeSecret, _, kFakeCred, _, _, _,
                               _, _, _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  auto result = backend_->GetPinWeaverTpm2().CheckCredential(
      kLabel, kHAux, brillo::BlobFromString(kFakeCred), kFakeLeSecret);

  EXPECT_FALSE(result.ok());
}

TEST_F(BackendPinweaverTpm2Test, RemoveCredential) {
  constexpr uint32_t kVersion = 1;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeMac = "fake_mac";
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverRemoveLeaf(kVersion, kLabel, _, kFakeMac, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(0), SetArgPointee<5>(kFakeRoot),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().RemoveCredential(
      kLabel, kHAux, brillo::BlobFromString(kFakeMac));

  ASSERT_OK(result);
  EXPECT_EQ(result->error, ErrorCode::kSuccess);
  EXPECT_EQ(result->new_root, brillo::BlobFromString(kFakeRoot));
}

TEST_F(BackendPinweaverTpm2Test, RemoveCredentialFail) {
  constexpr uint32_t kVersion = 1;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeMac = "fake_mac";
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverRemoveLeaf(kVersion, kLabel, _, kFakeMac, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(PW_ERR_HMAC_AUTH_FAILED),
                      SetArgPointee<5>(kFakeRoot),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().RemoveCredential(
      kLabel, kHAux, brillo::BlobFromString(kFakeMac));

  EXPECT_FALSE(result.ok());
}

TEST_F(BackendPinweaverTpm2Test, ResetCredential) {
  constexpr uint32_t kVersion = 2;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      PinWeaverResetAuth(kVersion, kFakeResetSecret, /*strong_reset=*/true, _,
                         kFakeCred, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(0), SetArgPointee<6>(kFakeRoot),
                      SetArgPointee<7>(kNewCred), SetArgPointee<8>(kFakeMac),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().ResetCredential(
      kLabel, kHAux, brillo::BlobFromString(kFakeCred), kFakeResetSecret,
      /*strong_reset=*/true);

  ASSERT_OK(result);
  EXPECT_EQ(result->error, ErrorCode::kSuccess);
  EXPECT_EQ(result->new_root, brillo::BlobFromString(kFakeRoot));
  ASSERT_TRUE(result->new_cred_metadata.has_value());
  EXPECT_EQ(result->new_cred_metadata.value(),
            brillo::BlobFromString(kNewCred));
  ASSERT_TRUE(result->new_mac.has_value());
  EXPECT_EQ(result->new_mac.value(), brillo::BlobFromString(kFakeMac));
}

TEST_F(BackendPinweaverTpm2Test, ResetCredentialV1ExpirationUnsupported) {
  constexpr uint32_t kVersion = 1;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().ResetCredential(
      kLabel, kHAux, brillo::BlobFromString(kFakeCred), kFakeResetSecret,
      /*strong_reset=*/true);

  ASSERT_NOT_OK(result);
}

TEST_F(BackendPinweaverTpm2Test, GetLog) {
  constexpr uint32_t kVersion = 1;
  const std::string kFakeRoot = "fake_root";
  const std::string kNewRoot = "new_root";

  trunks::PinWeaverLogEntry entry1;
  entry1.set_label(42);
  entry1.set_root(kNewRoot);
  entry1.mutable_insert_leaf()->set_hmac("fake_mac");

  trunks::PinWeaverLogEntry entry2;
  entry2.set_label(42);
  entry2.set_root(kFakeRoot);

  trunks::PinWeaverLogEntry entry3;
  entry3.set_label(43);
  entry3.set_root(kFakeRoot);
  entry3.mutable_remove_leaf();

  trunks::PinWeaverLogEntry entry4;
  entry4.set_label(44);
  entry4.set_root(kNewRoot);
  entry4.mutable_reset_tree();

  const std::vector<trunks::PinWeaverLogEntry> kFakeLog = {entry1, entry2,
                                                           entry3, entry4};

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverGetLog(kVersion, kFakeRoot, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(0), SetArgPointee<3>(kNewRoot),
                      SetArgPointee<4>(kFakeLog),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result =
      backend_->GetPinWeaverTpm2().GetLog(brillo::BlobFromString(kFakeRoot));

  ASSERT_OK(result);
  EXPECT_EQ(result->root_hash, brillo::BlobFromString(kNewRoot));
  EXPECT_EQ(result->log_entries.size(), kFakeLog.size());
}

TEST_F(BackendPinweaverTpm2Test, GetLogFail) {
  constexpr uint32_t kVersion = 1;
  const std::string kFakeRoot = "fake_root";
  const std::string kNewRoot = "new_root";

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverGetLog(kVersion, kFakeRoot, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(PW_ERR_TREE_INVALID),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result =
      backend_->GetPinWeaverTpm2().GetLog(brillo::BlobFromString(kFakeRoot));

  EXPECT_FALSE(result.ok());
}

TEST_F(BackendPinweaverTpm2Test, ReplayLogOperation) {
  constexpr uint32_t kVersion = 1;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeHeSecret("fake_he_secret");
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverLogReplay(kVersion, kFakeRoot, _, kFakeCred, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(0), SetArgPointee<5>(kFakeRoot),
                      SetArgPointee<6>(kNewCred), SetArgPointee<7>(kFakeMac),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().ReplayLogOperation(
      brillo::BlobFromString(kFakeRoot), kHAux,
      brillo::BlobFromString(kFakeCred));

  ASSERT_OK(result);
  EXPECT_EQ(result->new_cred_metadata, brillo::BlobFromString(kNewCred));
  EXPECT_EQ(result->new_mac, brillo::BlobFromString(kFakeMac));
}

TEST_F(BackendPinweaverTpm2Test, ReplayLogOperationFail) {
  constexpr uint32_t kVersion = 1;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeHeSecret("fake_he_secret");
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverLogReplay(kVersion, kFakeRoot, _, kFakeCred, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(PW_ERR_ROOT_NOT_FOUND),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().ReplayLogOperation(
      brillo::BlobFromString(kFakeRoot), kHAux,
      brillo::BlobFromString(kFakeCred));

  EXPECT_FALSE(result.ok());
}

TEST_F(BackendPinweaverTpm2Test, GetWrongAuthAttempts) {
  brillo::Blob header(sizeof(unimported_leaf_data_t));
  brillo::Blob leaf(sizeof(leaf_public_data_t));

  struct leaf_public_data_t* leaf_data =
      reinterpret_cast<struct leaf_public_data_t*>(leaf.data());
  leaf_data->attempt_count.v = 123;

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetWrongAuthAttempts(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(123));
}

TEST_F(BackendPinweaverTpm2Test, GetWrongAuthAttemptsEmpty) {
  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetWrongAuthAttempts(brillo::Blob()),
              NotOk());
}

TEST_F(BackendPinweaverTpm2Test, GetDelaySchedule) {
  brillo::Blob header(sizeof(unimported_leaf_data_t));
  brillo::Blob leaf(sizeof(leaf_public_data_t));

  struct leaf_public_data_t* leaf_data =
      reinterpret_cast<struct leaf_public_data_t*>(leaf.data());
  leaf_data->delay_schedule[0].attempt_count.v = 5;
  leaf_data->delay_schedule[0].time_diff.v = UINT32_MAX;

  auto result = backend_->GetPinWeaverTpm2().GetDelaySchedule(
      brillo::CombineBlobs({header, leaf}));

  ASSERT_OK(result);
  ASSERT_EQ(result.value().size(), 1);
  EXPECT_EQ(result.value().begin()->first, 5);
  EXPECT_EQ(result.value().begin()->second, UINT32_MAX);
}

TEST_F(BackendPinweaverTpm2Test, GetDelayScheduleEmpty) {
  auto result = backend_->GetPinWeaverTpm2().GetDelaySchedule(brillo::Blob());

  EXPECT_FALSE(result.ok());
}

TEST_F(BackendPinweaverTpm2Test, GetDelayInSecondsV1) {
  brillo::Blob header(sizeof(unimported_leaf_data_t));
  brillo::Blob leaf(sizeof(leaf_public_data_t));

  struct leaf_public_data_t* leaf_data =
      reinterpret_cast<struct leaf_public_data_t*>(leaf.data());
  leaf_data->delay_schedule[0].attempt_count.v = 5;
  leaf_data->delay_schedule[0].time_diff.v = UINT32_MAX;
  leaf_data->attempt_count.v = 4;

  // In version 1, GetDelayInSeconds only parses the cred metadata, without
  // initiating any requests to the PinWeaver server.
  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(1), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetDelayInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(0));

  leaf_data->attempt_count.v = 5;

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetDelayInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(UINT32_MAX));
}

TEST_F(BackendPinweaverTpm2Test, GetDelayInSecondsV2) {
  const std::string kFakeRoot = "fake_root";

  brillo::Blob header(sizeof(unimported_leaf_data_t));
  brillo::Blob leaf(sizeof(leaf_public_data_t));

  struct leaf_public_data_t* leaf_data =
      reinterpret_cast<struct leaf_public_data_t*>(leaf.data());
  leaf_data->delay_schedule[0].attempt_count.v = 5;
  leaf_data->delay_schedule[0].time_diff.v = 60;
  leaf_data->delay_schedule[1].attempt_count.v = 6;
  leaf_data->delay_schedule[1].time_diff.v = 70;
  leaf_data->delay_schedule[2].attempt_count.v = 7;
  leaf_data->delay_schedule[2].time_diff.v = UINT32_MAX;
  leaf_data->last_access_ts.boot_count = 0;
  leaf_data->last_access_ts.timer_value = 100;
  leaf_data->attempt_count.v = 4;

  // In version 2, GetDelayInSeconds requests the current timestamp from the
  // PinWeaver server, so that it can return a more accurate remaining seconds.
  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(2), Return(trunks::TPM_RC_SUCCESS)));

  // This is only called twice because when the delay is infinite, we don't have
  // to query the current timestamp.
  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverSysInfo(2, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(0), SetArgPointee<2>(kFakeRoot),
                      SetArgPointee<3>(0), SetArgPointee<4>(120),
                      Return(trunks::TPM_RC_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<1>(0), SetArgPointee<2>(kFakeRoot),
                      SetArgPointee<3>(1), SetArgPointee<4>(10),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetDelayInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(0));

  // Ready timestamp is 100+60=160, and the current timestamp is 120.
  leaf_data->attempt_count.v = 5;

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetDelayInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(40));

  // Ready timestamp is 70 because the boot count has changed, and the current
  // timestamp is 10.
  leaf_data->attempt_count.v = 6;

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetDelayInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(60));

  // Ready timestamp isn't important because the leaf is infinitely locked out.
  leaf_data->attempt_count.v = 7;

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetDelayInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(UINT32_MAX));
}

TEST_F(BackendPinweaverTpm2Test, GetExpirationInSecondsV1) {
  constexpr uint32_t kVersion = 1;
  const std::string kFakeRoot = "fake_root";

  brillo::Blob header(sizeof(unimported_leaf_data_t));
  brillo::Blob leaf(sizeof(leaf_public_data_t));

  struct leaf_public_data_t* leaf_data =
      reinterpret_cast<struct leaf_public_data_t*>(leaf.data());
  leaf_data->expiration_delay_s.v = 10;
  leaf_data->expiration_ts.boot_count = 1;
  leaf_data->expiration_ts.timer_value = 120;

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  // In version 1, credentials are always treated as having no expiration.
  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetExpirationInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(std::nullopt));
}

TEST_F(BackendPinweaverTpm2Test, GetExpirationInSecondsV2) {
  constexpr uint32_t kVersion = 2;
  const std::string kFakeRoot = "fake_root";

  brillo::Blob header(sizeof(unimported_leaf_data_t));
  brillo::Blob leaf(sizeof(leaf_public_data_t));
  // Simulate a leaf created at v1.
  brillo::Blob leaf_v1(offsetof(leaf_public_data_t, expiration_ts));

  struct leaf_public_data_t* leaf_data =
      reinterpret_cast<struct leaf_public_data_t*>(leaf.data());
  leaf_data->expiration_delay_s.v = 0;
  leaf_data->expiration_ts.boot_count = 0;
  leaf_data->expiration_ts.timer_value = 0;

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  // This is only called 3 times because when the delay is 0, we don't have
  // to query the current timestamp.
  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverSysInfo(kVersion, _, _, _, _))
      .Times(3)
      .WillRepeatedly(DoAll(SetArgPointee<1>(0), SetArgPointee<2>(kFakeRoot),
                            SetArgPointee<3>(1), SetArgPointee<4>(100),
                            Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetExpirationInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(std::nullopt));

  leaf_data->expiration_delay_s.v = 10;
  leaf_data->expiration_ts.timer_value = 120;

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetExpirationInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(0));

  leaf_data->expiration_ts.boot_count = 1;
  leaf_data->expiration_ts.timer_value = 80;

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetExpirationInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(0));

  leaf_data->expiration_ts.timer_value = 120;

  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetExpirationInSeconds(
                  brillo::CombineBlobs({header, leaf})),
              IsOkAndHolds(20));

  // Leaf created in version before v2 has no expiration.
  EXPECT_THAT(backend_->GetPinWeaverTpm2().GetExpirationInSeconds(
                  brillo::CombineBlobs({header, leaf_v1})),
              IsOkAndHolds(std::nullopt));
}

TEST_F(BackendPinweaverTpm2Test, GeneratePk) {
  constexpr uint32_t kVersion = 2;
  constexpr uint8_t kAuthChannel = 0;
  const std::string kFakeRoot = "fake_root";
  const std::string kClientCoordinate(32, 'A');
  const std::string kServerCoordinate(32, 'B');

  Backend::PinWeaver::PinWeaverEccPoint client_public_key;
  memcpy(client_public_key.x, kClientCoordinate.data(),
         kClientCoordinate.size());
  memcpy(client_public_key.y, kClientCoordinate.data(),
         kClientCoordinate.size());
  trunks::PinWeaverEccPoint server_public_key;
  memcpy(server_public_key.x, kServerCoordinate.data(),
         kServerCoordinate.size());
  memcpy(server_public_key.y, kServerCoordinate.data(),
         kServerCoordinate.size());

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      PinWeaverGenerateBiometricsAuthPk(kVersion, kAuthChannel, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(0), SetArgPointee<4>(kFakeRoot),
                      SetArgPointee<5>(server_public_key),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result =
      backend_->GetPinWeaverTpm2().GeneratePk(kAuthChannel, client_public_key);

  ASSERT_OK(result);
  ASSERT_FALSE(memcmp(&*result, &server_public_key, 64));
}

TEST_F(BackendPinweaverTpm2Test, GeneratePkV1Unsupported) {
  constexpr uint32_t kVersion = 1;
  constexpr uint8_t kAuthChannel = 0;
  const std::string kClientCoordinate(32, 'A');

  Backend::PinWeaver::PinWeaverEccPoint client_public_key;
  memcpy(client_public_key.x, kClientCoordinate.data(),
         kClientCoordinate.size());
  memcpy(client_public_key.y, kClientCoordinate.data(),
         kClientCoordinate.size());

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(
      backend_->GetPinWeaverTpm2().GeneratePk(kAuthChannel, client_public_key),
      NotOk());
}

TEST_F(BackendPinweaverTpm2Test, GeneratePkInvalidAuthChannel) {
  constexpr uint32_t kVersion = 2;
  constexpr uint8_t kAuthChannel = 2;
  const std::string kClientCoordinate(32, 'A');

  Backend::PinWeaver::PinWeaverEccPoint client_public_key;
  memcpy(client_public_key.x, kClientCoordinate.data(),
         kClientCoordinate.size());
  memcpy(client_public_key.y, kClientCoordinate.data(),
         kClientCoordinate.size());

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(
      backend_->GetPinWeaverTpm2().GeneratePk(kAuthChannel, client_public_key),
      NotOk());
}

TEST_F(BackendPinweaverTpm2Test, InsertRateLimiter) {
  constexpr uint32_t kVersion = 2;
  constexpr uint8_t kAuthChannel = 0;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const hwsec::Backend::PinWeaver::DelaySchedule kDelaySched = {
      {5, UINT32_MAX},
  };
  const uint32_t kExpirationDelay = 100;
  const std::vector<OperationPolicySetting> kPolicies = {
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = std::nullopt,
                      },
              },
      },
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{
                  .current_user =
                      DeviceConfigSettings::CurrentUserSetting{
                          .username = "fake_username",
                      },
              },
      },
  };
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverCreateBiometricsAuthRateLimiter(
                  kVersion, kAuthChannel, kLabel, _, kFakeResetSecret,
                  kDelaySched, _, Eq(kExpirationDelay), _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<8>(0), SetArgPointee<9>(kFakeRoot),
                      SetArgPointee<10>(kFakeCred), SetArgPointee<11>(kFakeMac),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().InsertRateLimiter(
      kAuthChannel, kPolicies, kLabel, kHAux, kFakeResetSecret, kDelaySched,
      kExpirationDelay);

  ASSERT_OK(result);
  EXPECT_EQ(result->error, ErrorCode::kSuccess);
  EXPECT_EQ(result->new_root, brillo::BlobFromString(kFakeRoot));
  ASSERT_TRUE(result->new_cred_metadata.has_value());
  EXPECT_EQ(result->new_cred_metadata.value(),
            brillo::BlobFromString(kFakeCred));
  ASSERT_TRUE(result->new_mac.has_value());
  EXPECT_EQ(result->new_mac.value(), brillo::BlobFromString(kFakeMac));
}

TEST_F(BackendPinweaverTpm2Test, InsertRateLimiterV1Unsupported) {
  constexpr uint32_t kVersion = 1;
  constexpr uint8_t kAuthChannel = 0;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const hwsec::Backend::PinWeaver::DelaySchedule kDelaySched = {
      {5, UINT32_MAX},
  };
  const uint32_t kExpirationDelay = 100;
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(
      backend_->GetPinWeaverTpm2().InsertRateLimiter(
          kAuthChannel, /*policies=*/std::vector<OperationPolicySetting>(),
          kLabel, kHAux, kFakeResetSecret, kDelaySched, kExpirationDelay),
      NotOk());
}

TEST_F(BackendPinweaverTpm2Test, InsertRateLimiterInvalidAuthChannel) {
  constexpr uint32_t kVersion = 2;
  constexpr uint8_t kAuthChannel = 2;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::SecureBlob kFakeResetSecret("fake_reset_secret");
  const hwsec::Backend::PinWeaver::DelaySchedule kDelaySched = {
      {5, UINT32_MAX},
  };
  const uint32_t kExpirationDelay = 100;
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(
      backend_->GetPinWeaverTpm2().InsertRateLimiter(
          kAuthChannel, /*policies=*/std::vector<OperationPolicySetting>(),
          kLabel, kHAux, kFakeResetSecret, kDelaySched, kExpirationDelay),
      NotOk());
}

TEST_F(BackendPinweaverTpm2Test, StartBiometricsAuth) {
  constexpr uint32_t kVersion = 2;
  constexpr uint8_t kAuthChannel = 0;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::Blob kFakeClientNonce =
      brillo::BlobFromString("fake_client_nonce");
  const brillo::Blob kFakeServerNonce =
      brillo::BlobFromString("fake_server_nonce");
  const brillo::Blob kFakeEncryptedHeSecret =
      brillo::BlobFromString("fake_encrypted_he_secret");
  const brillo::Blob kFakeIv = brillo::BlobFromString("fake_iv");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      PinWeaverStartBiometricsAuth(kVersion, kAuthChannel, kFakeClientNonce, _,
                                   kFakeCred, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(0), SetArgPointee<6>(kFakeRoot),
                      SetArgPointee<7>(kFakeServerNonce),
                      SetArgPointee<8>(kFakeEncryptedHeSecret),
                      SetArgPointee<9>(kFakeIv), SetArgPointee<10>(kNewCred),
                      SetArgPointee<11>(kFakeMac),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().StartBiometricsAuth(
      kAuthChannel, kLabel, kHAux, brillo::BlobFromString(kFakeCred),
      kFakeClientNonce);

  ASSERT_OK(result);
  EXPECT_EQ(result->error, ErrorCode::kSuccess);
  EXPECT_EQ(result->new_root, brillo::BlobFromString(kFakeRoot));
  ASSERT_TRUE(result->new_cred_metadata.has_value());
  EXPECT_EQ(result->new_cred_metadata.value(),
            brillo::BlobFromString(kNewCred));
  ASSERT_TRUE(result->new_mac.has_value());
  EXPECT_EQ(result->new_mac.value(), brillo::BlobFromString(kFakeMac));
  ASSERT_TRUE(result->server_nonce.has_value());
  EXPECT_EQ(result->server_nonce.value(), kFakeServerNonce);
  ASSERT_TRUE(result->encrypted_he_secret.has_value());
  EXPECT_EQ(result->encrypted_he_secret.value(), kFakeEncryptedHeSecret);
  ASSERT_TRUE(result->iv.has_value());
  EXPECT_EQ(result->iv.value(), kFakeIv);
}

TEST_F(BackendPinweaverTpm2Test, StartBiometricsAuthAuthFail) {
  constexpr uint32_t kVersion = 2;
  constexpr uint8_t kWrongAuthChannel = 1;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::Blob kFakeClientNonce =
      brillo::BlobFromString("fake_client_nonce");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverStartBiometricsAuth(kVersion, kWrongAuthChannel,
                                           kFakeClientNonce, _, kFakeCred, _, _,
                                           _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(PW_ERR_LOWENT_AUTH_FAILED),
                      SetArgPointee<6>(kFakeRoot), SetArgPointee<10>(kNewCred),
                      SetArgPointee<11>(kFakeMac),
                      Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetPinWeaverTpm2().StartBiometricsAuth(
      kWrongAuthChannel, kLabel, kHAux, brillo::BlobFromString(kFakeCred),
      kFakeClientNonce);

  ASSERT_OK(result);
  EXPECT_EQ(result->error, ErrorCode::kInvalidLeSecret);
  EXPECT_EQ(result->new_root, brillo::BlobFromString(kFakeRoot));
  ASSERT_TRUE(result->new_cred_metadata.has_value());
  EXPECT_EQ(result->new_cred_metadata.value(),
            brillo::BlobFromString(kNewCred));
  ASSERT_TRUE(result->new_mac.has_value());
  EXPECT_EQ(result->new_mac.value(), brillo::BlobFromString(kFakeMac));
  ASSERT_TRUE(result->server_nonce.has_value());
  EXPECT_TRUE(result->server_nonce->empty());
  ASSERT_TRUE(result->encrypted_he_secret.has_value());
  EXPECT_TRUE(result->encrypted_he_secret->empty());
  ASSERT_TRUE(result->iv.has_value());
  EXPECT_TRUE(result->iv->empty());
}

TEST_F(BackendPinweaverTpm2Test, StartBiometricsAuthTpmFail) {
  constexpr uint32_t kVersion = 2;
  constexpr uint8_t kAuthChannel = 0;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::Blob kFakeClientNonce =
      brillo::BlobFromString("fake_client_nonce");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(
      proxy_->GetMockTpmUtility(),
      PinWeaverStartBiometricsAuth(kVersion, kAuthChannel, kFakeClientNonce, _,
                                   kFakeCred, _, _, _, _, _, _, _))
      .WillOnce(Return(trunks::TPM_RC_FAILURE));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().StartBiometricsAuth(
                  kAuthChannel, kLabel, kHAux,
                  brillo::BlobFromString(kFakeCred), kFakeClientNonce),
              NotOk());
}

TEST_F(BackendPinweaverTpm2Test, StartBiometricsAuthV1NotSupported) {
  constexpr uint32_t kVersion = 1;
  constexpr uint8_t kAuthChannel = 0;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::Blob kFakeClientNonce =
      brillo::BlobFromString("fake_client_nonce");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().StartBiometricsAuth(
                  kAuthChannel, kLabel, kHAux,
                  brillo::BlobFromString(kFakeCred), kFakeClientNonce),
              NotOk());
}

TEST_F(BackendPinweaverTpm2Test, StartBiometricsAuthInvalidAuthChannel) {
  constexpr uint32_t kVersion = 2;
  constexpr uint8_t kAuthChannel = 2;
  constexpr uint32_t kLabel = 42;
  const std::string kFakeRoot = "fake_root";
  const std::string kFakeCred = "fake_cred";
  const std::string kNewCred = "new_cred";
  const std::string kFakeMac = "fake_mac";
  const brillo::Blob kFakeClientNonce =
      brillo::BlobFromString("fake_client_nonce");
  const std::vector<brillo::Blob>& kHAux = {
      brillo::Blob(32, 'X'),
      brillo::Blob(32, 'Y'),
      brillo::Blob(32, 'Z'),
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().StartBiometricsAuth(
                  kAuthChannel, kLabel, kHAux,
                  brillo::BlobFromString(kFakeCred), kFakeClientNonce),
              NotOk());
}

TEST_F(BackendPinweaverTpm2Test, BlockGeneratePk) {
  constexpr uint32_t kVersion = 2;
  const std::string kFakeRoot = "fake_root";

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              PinWeaverBlockGenerateBiometricsAuthPk(kVersion, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(0), SetArgPointee<2>(kFakeRoot),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().BlockGeneratePk(), IsOk());
}

TEST_F(BackendPinweaverTpm2Test, BlockGeneratePkV1NotSupported) {
  constexpr uint32_t kVersion = 1;

  EXPECT_CALL(proxy_->GetMockTpmUtility(), PinWeaverIsSupported(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kVersion), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetPinWeaverTpm2().BlockGeneratePk(), NotOk());
}

}  // namespace hwsec
