// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>
#include <trunks/mock_tpm_utility.h>

#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"

// Prevent the conflict definition from tss.h
#undef TPM_ALG_RSA

using hwsec_foundation::Sha256;
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

using BackendDeriveTpm2Test = BackendTpm2TestBase;

TEST_F(BackendDeriveTpm2Test, DeriveSecureRsa) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const std::string kFakeBlob(256, 'X');
  const std::string kFakeOutput = "fake_output";
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_RSA,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
      .parameters =
          trunks::TPMU_PUBLIC_PARMS{
              .rsa_detail =
                  trunks::TPMS_RSA_PARMS{
                      .symmetric =
                          trunks::TPMT_SYM_DEF_OBJECT{
                              .algorithm = trunks::TPM_ALG_NULL,
                          },
                      .scheme =
                          trunks::TPMT_RSA_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                      .key_bits = 2048,
                      .exponent = 0,
                  },
          },
      .unique =
          trunks::TPMU_PUBLIC_ID{
              .rsa =
                  trunks::TPM2B_PUBLIC_KEY_RSA{
                      .size = 10,
                      .buffer = "9876543210",
                  },
          },
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              AsymmetricDecrypt(kFakeKeyHandle, trunks::TPM_ALG_NULL,
                                trunks::TPM_ALG_NULL, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<5>(kFakeOutput), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetDerivingTpm2().SecureDerive(
                  key->GetKey(), brillo::SecureBlob(kFakeBlob)),
              IsOkAndHolds(Sha256(brillo::SecureBlob(kFakeOutput))));
}

TEST_F(BackendDeriveTpm2Test, DeriveEcc) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const std::string kFakeBlob(256, 'X');
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_ECC,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
      .parameters =
          trunks::TPMU_PUBLIC_PARMS{
              .ecc_detail =
                  trunks::TPMS_ECC_PARMS{
                      .symmetric =
                          trunks::TPMT_SYM_DEF_OBJECT{
                              .algorithm = trunks::TPM_ALG_NULL,
                          },
                      .scheme =
                          trunks::TPMT_ECC_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                      .curve_id = trunks::TPM_ECC_NIST_P256,
                      .kdf =
                          trunks::TPMT_KDF_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                  },
          },
      .unique =
          trunks::TPMU_PUBLIC_ID{
              .ecc =
                  trunks::TPMS_ECC_POINT{
                      .x =
                          trunks::TPM2B_ECC_PARAMETER{
                              .size = 10,
                              .buffer = "0123456789",
                          },
                      .y = trunks::TPM2B_ECC_PARAMETER{.size = 0},
                  },
          },
  };
  const trunks::TPM2B_ECC_POINT kFakeZPoint{
      .size = 2 + 10 + 2,
      .point =
          trunks::TPMS_ECC_POINT{
              .x =
                  trunks::TPM2B_ECC_PARAMETER{
                      .size = 10,
                      .buffer = "9876543210",
                  },
              .y = trunks::TPM2B_ECC_PARAMETER{.size = 0},
          },
  };

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ECDHZGen(kFakeKeyHandle, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(kFakeZPoint), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_THAT(backend_->GetDerivingTpm2().Derive(
                  key->GetKey(), brillo::BlobFromString(kFakeBlob)),
              IsOkAndHolds(Sha256(brillo::BlobFromString("9876543210"))));
}

TEST_F(BackendDeriveTpm2Test, DeriveEccOutOfRange) {
  const OperationPolicy kFakePolicy{};
  const std::string kFakeKeyBlob = "fake_key_blob";
  const uint32_t kFakeKeyHandle = 0x1337;
  const std::string kOorStr =
      "AD1FE60D4FF828511B829DA029F98A1A164C4C946776AC1A4DEF3D490371BB66";
  const trunks::TPMT_PUBLIC kFakePublic = {
      .type = trunks::TPM_ALG_ECC,
      .name_alg = trunks::TPM_ALG_SHA256,
      .object_attributes = trunks::kFixedTPM | trunks::kFixedParent,
      .auth_policy = trunks::TPM2B_DIGEST{.size = 0},
      .parameters =
          trunks::TPMU_PUBLIC_PARMS{
              .ecc_detail =
                  trunks::TPMS_ECC_PARMS{
                      .symmetric =
                          trunks::TPMT_SYM_DEF_OBJECT{
                              .algorithm = trunks::TPM_ALG_NULL,
                          },
                      .scheme =
                          trunks::TPMT_ECC_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                      .curve_id = trunks::TPM_ECC_NIST_P256,
                      .kdf =
                          trunks::TPMT_KDF_SCHEME{
                              .scheme = trunks::TPM_ALG_NULL,
                          },
                  },
          },
      .unique =
          trunks::TPMU_PUBLIC_ID{
              .ecc =
                  trunks::TPMS_ECC_POINT{
                      .x =
                          trunks::TPM2B_ECC_PARAMETER{
                              .size = 10,
                              .buffer = "0123456789",
                          },
                      .y = trunks::TPM2B_ECC_PARAMETER{.size = 0},
                  },
          },
  };

  brillo::Blob fake_blob;
  base::HexStringToBytes(kOorStr, &fake_blob);

  EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  auto key = backend_->GetKeyManagementTpm2().LoadKey(
      kFakePolicy, brillo::BlobFromString(kFakeKeyBlob),
      Backend::KeyManagement::LoadKeyOptions{});

  ASSERT_OK(key);

  auto result = backend_->GetDerivingTpm2().Derive(key->GetKey(), fake_blob);

  ASSERT_NOT_OK(result);
  EXPECT_EQ(result.err_status()->ToTPMRetryAction(),
            TPMRetryAction::kEllipticCurveScalarOutOfRange);
}

}  // namespace hwsec
