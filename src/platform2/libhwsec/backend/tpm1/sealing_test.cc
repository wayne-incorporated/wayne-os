// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"
#include "libhwsec/overalls/mock_overalls.h"

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

using BackendSealingTpm1Test = BackendTpm1TestBase;

TEST_F(BackendSealingTpm1Test, Seal) {
  const brillo::SecureBlob kFakeAuthValue("auth_value");
  const OperationPolicySetting kFakePolicy{
      .device_config_settings =
          DeviceConfigSettings{
              .current_user =
                  DeviceConfigSettings::CurrentUserSetting{
                      .username = std::nullopt,
                  },
          },
      .permission =
          Permission{
              .auth_value = kFakeAuthValue,
          },
  };
  const brillo::SecureBlob kFakeUnsealedData("unsealed_data");
  const brillo::Blob kFakeSealedData = brillo::BlobFromString("sealed_data");
  const uint32_t kFakeEncHandle = 0x1337;
  const uint32_t kFakePcrHandle = 0x7331;
  const TSS_HPOLICY kFakeHPolicy = 0x94123;

  SetupSrk();

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_PCRS,
                                        TSS_PCRS_STRUCT_INFO, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakePcrHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_PcrComposite_SetPcrValue(kFakePcrHandle, _, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_ENCDATA,
                                TSS_ENCDATA_SEAL, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeEncHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetPolicyObject(kDefaultTpm, TSS_POLICY_USAGE, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeHPolicy), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_SetSecret(kFakeHPolicy, TSS_SECRET_MODE_PLAIN, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakeHPolicy, kFakeEncHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Data_Seal(kFakeEncHandle, kDefaultSrkHandle, _, _, kFakePcrHandle))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob sealed_data = kFakeSealedData;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeEncHandle, TSS_TSPATTRIB_ENCDATA_BLOB,
                                 TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(sealed_data.size()),
                      SetArgPointee<4>(sealed_data.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_THAT(backend_->GetSealingTpm1().Seal(kFakePolicy, kFakeUnsealedData),
              IsOkAndHolds(kFakeSealedData));
}

TEST_F(BackendSealingTpm1Test, PreloadSealedData) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeSealedData = "fake_sealed_data";

  auto result = backend_->GetSealingTpm1().PreloadSealedData(
      kFakePolicy, brillo::BlobFromString(kFakeSealedData));

  ASSERT_OK(result);
  EXPECT_FALSE(result->has_value());
}

TEST_F(BackendSealingTpm1Test, Unseal) {
  const brillo::SecureBlob kFakeAuthValue("fake_auth_value");
  const OperationPolicy kFakePolicy{
      .device_configs = DeviceConfigs{DeviceConfig::kCurrentUser},
      .permission =
          Permission{
              .auth_value = kFakeAuthValue,
          },
  };
  const brillo::SecureBlob kFakeUnsealedData("fake_data");
  const brillo::Blob kFakeSealedData =
      brillo::BlobFromString("fake_sealed_data");
  const uint32_t kFakeEncHandle = 0x1337;
  const TSS_HPOLICY kFakeHPolicy = 0x94123;

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_ENCDATA,
                                TSS_ENCDATA_SEAL, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeEncHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetPolicyObject(kDefaultTpm, TSS_POLICY_USAGE, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeHPolicy), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_SetSecret(kFakeHPolicy, TSS_SECRET_MODE_PLAIN, _, _))
      .WillOnce([&](auto&&, auto&&, size_t auth_size, uint8_t* auth_ptr) {
        EXPECT_EQ(kFakeAuthValue,
                  brillo::SecureBlob(auth_ptr, auth_ptr + auth_size));
        return TPM_SUCCESS;
      });

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakeHPolicy, kFakeEncHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeEncHandle, TSS_TSPATTRIB_ENCDATA_BLOB,
                                 TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::SecureBlob unsealed_data = kFakeUnsealedData;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Data_Unseal(kFakeEncHandle, kDefaultSrkHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(unsealed_data.size()),
                      SetArgPointee<3>(unsealed_data.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_THAT(
      backend_->GetSealingTpm1().Unseal(kFakePolicy, kFakeSealedData,
                                        Backend::Sealing::UnsealOptions{}),
      IsOkAndHolds(kFakeUnsealedData));
}

}  // namespace hwsec
