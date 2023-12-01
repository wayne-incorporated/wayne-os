// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <utility>

#include <base/hash/sha1.h>
#include <crypto/sha2.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <openssl/sha.h>
#include <trunks/mock_tpm_utility.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"

using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using tpm_manager::TpmManagerStatus;
namespace hwsec {

using BackendConfigTpm2Test = BackendTpm2TestBase;

TEST_F(BackendConfigTpm2Test, ToOperationPolicy) {
  const brillo::SecureBlob kFakeAuthValue("auth_value");
  const OperationPolicySetting kFakeSetting = {
      .device_config_settings =
          DeviceConfigSettings{
              .boot_mode =
                  DeviceConfigSettings::BootModeSetting{
                      .mode =
                          DeviceConfigSettings::BootModeSetting::Mode{
                              .developer_mode = true,
                              .recovery_mode = true,
                              .verified_firmware = true,
                          },
                  },
              .device_model =
                  DeviceConfigSettings::DeviceModelSetting{
                      .hardware_id = "ZZCR",
                  },
              .current_user =
                  DeviceConfigSettings::CurrentUserSetting{
                      .username = "username",
                  },
          },
      .permission =
          Permission{
              .auth_value = kFakeAuthValue,
          },
  };

  auto result = backend_->GetConfigTpm2().ToOperationPolicy(kFakeSetting);

  ASSERT_OK(result);
  ASSERT_TRUE(result->permission.auth_value.has_value());
  EXPECT_EQ(result->permission.auth_value.value(), kFakeAuthValue);
  EXPECT_EQ(result->device_configs, (DeviceConfigs{
                                        DeviceConfig::kBootMode,
                                        DeviceConfig::kDeviceModel,
                                        DeviceConfig::kCurrentUser,
                                    }));
}

TEST_F(BackendConfigTpm2Test, SetCurrentUser) {
  const std::string kFakeUser = "fake_user";

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ExtendPCR(_, kFakeUser, _))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ExtendPCRForCSME(_, kFakeUser))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  auto result = backend_->GetConfigTpm2().SetCurrentUser(kFakeUser);

  EXPECT_TRUE(result.ok());
}

TEST_F(BackendConfigTpm2Test, IsCurrentUserSet) {
  const std::string kNonZeroPcr(SHA256_DIGEST_LENGTH, 'X');

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kNonZeroPcr), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetConfigTpm2().IsCurrentUserSet(), IsOkAndHolds(true));
}

TEST_F(BackendConfigTpm2Test, IsCurrentUserSetZero) {
  const std::string kZeroPcr(SHA256_DIGEST_LENGTH, 0);

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kZeroPcr), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetConfigTpm2().IsCurrentUserSet(),
              IsOkAndHolds(false));
}

TEST_F(BackendConfigTpm2Test, GetCurrentBootMode) {
  DeviceConfigSettings::BootModeSetting::Mode fake_mode = {
      .developer_mode = false,
      .recovery_mode = true,
      .verified_firmware = false,
  };
  char boot_modes[3] = {fake_mode.developer_mode, fake_mode.recovery_mode,
                        fake_mode.verified_firmware};
  std::string mode_string =
      std::string(std::begin(boot_modes), std::end(boot_modes));
  std::string mode_digest = base::SHA1HashString(mode_string);
  mode_digest.resize(crypto::kSHA256Length);

  const std::string pcr_initial_value(crypto::kSHA256Length, 0);
  const std::string kValidPcr =
      crypto::SHA256HashString(pcr_initial_value + mode_digest);

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kValidPcr), Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetConfigTpm2().GetCurrentBootMode();
  ASSERT_OK(result);
  EXPECT_TRUE(result.value().developer_mode == fake_mode.developer_mode);
  EXPECT_TRUE(result.value().recovery_mode == fake_mode.recovery_mode);
  EXPECT_TRUE(result.value().verified_firmware == fake_mode.verified_firmware);
}

TEST_F(BackendConfigTpm2Test, GetCurrentBootModeInvalid) {
  const std::string kInvalidPcr(SHA256_DIGEST_LENGTH, 0);

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kInvalidPcr), Return(trunks::TPM_RC_SUCCESS)));

  auto result = backend_->GetConfigTpm2().GetCurrentBootMode();
  ASSERT_NOT_OK(result);
}

}  // namespace hwsec
