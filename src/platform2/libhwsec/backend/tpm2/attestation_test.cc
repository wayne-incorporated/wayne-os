// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <openssl/sha.h>
#include <trunks/mock_tpm.h>
#include <trunks/mock_tpm_utility.h>
#include <trunks/tpm_generated.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"
#include "libhwsec/structures/key.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;
using trunks::TPM_RC_FAILURE;
using trunks::TPM_RC_SUCCESS;

namespace hwsec {

class BackendAttestationTpm2Test : public BackendTpm2TestBase {
 protected:
  StatusOr<ScopedKey> LoadFakeRSAKey(const uint32_t fake_key_handle) {
    const OperationPolicy kFakePolicy{};
    const std::string kFakeKeyBlob = "fake_key_blob";
    const trunks::TPMT_PUBLIC kFakePublic = {
        .type = trunks::TPM_ALG_RSA,
    };

    EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
        .WillOnce(
            DoAll(SetArgPointee<2>(fake_key_handle), Return(TPM_RC_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockTpmUtility(),
                GetKeyPublicArea(fake_key_handle, _))
        .WillOnce(DoAll(SetArgPointee<1>(kFakePublic), Return(TPM_RC_SUCCESS)));

    return backend_->GetKeyManagementTpm2().LoadKey(
        kFakePolicy, BlobFromString(kFakeKeyBlob),
        Backend::KeyManagement::LoadKeyOptions{});
  }
  StatusOr<ScopedKey> LoadFakeECCKey(const uint32_t fake_key_handle) {
    const OperationPolicy kFakePolicy{};
    const std::string kFakeKeyBlob = "fake_key_blob";
    const trunks::TPMT_PUBLIC kFakePublic = {
        .type = trunks::TPM_ALG_ECC,
    };

    EXPECT_CALL(proxy_->GetMockTpmUtility(), LoadKey(kFakeKeyBlob, _, _))
        .WillOnce(
            DoAll(SetArgPointee<2>(fake_key_handle), Return(TPM_RC_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockTpmUtility(),
                GetKeyPublicArea(fake_key_handle, _))
        .WillOnce(DoAll(SetArgPointee<1>(kFakePublic), Return(TPM_RC_SUCCESS)));

    return backend_->GetKeyManagementTpm2().LoadKey(
        kFakePolicy, BlobFromString(kFakeKeyBlob),
        Backend::KeyManagement::LoadKeyOptions{});
  }
};

TEST_F(BackendAttestationTpm2Test, QuoteRsa) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode};
  const std::string kNonZeroPcr(SHA256_DIGEST_LENGTH, 'X');
  const std::string kFakeKeyName = "fake_key_name";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPM2B_ATTEST kFakeQuotedStruct =
      trunks::Make_TPM2B_ATTEST("fake_quoted_data");
  const trunks::TPMT_SIGNATURE kFakeSignature = {
      .sig_alg = trunks::TPM_ALG_RSASSA,
      .signature.rsassa.sig = trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_quote"),
  };

  auto load_key_result = LoadFakeRSAKey(kFakeKeyHandle);
  ASSERT_OK(load_key_result);
  const ScopedKey& fake_key = load_key_result.value();

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kNonZeroPcr), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyName(kFakeKeyHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeKeyName), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpm(),
              QuoteSync(kFakeKeyHandle, kFakeKeyName, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeQuotedStruct),
                      SetArgPointee<6>(kFakeSignature),
                      Return(TPM_RC_SUCCESS)));

  auto result = backend_->GetAttestationTpm2().Quote(kFakeDeviceConfigs,
                                                     fake_key.GetKey());
  ASSERT_OK(result);
  ASSERT_TRUE(result->has_quoted_pcr_value());
  EXPECT_EQ(result->quoted_pcr_value(), kNonZeroPcr);
  ASSERT_TRUE(result->has_quoted_data());
  EXPECT_EQ(result->quoted_data(), "fake_quoted_data");
  ASSERT_TRUE(result->has_quote());
  EXPECT_NE(result->quote().find("fake_quote"), std::string::npos);
  EXPECT_FALSE(result->has_pcr_source_hint());
}

TEST_F(BackendAttestationTpm2Test, QuoteEcc) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode};
  const std::string kNonZeroPcr(SHA256_DIGEST_LENGTH, 'X');
  const std::string kFakeKeyName = "fake_key_name";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPM2B_ATTEST kFakeQuotedStruct =
      trunks::Make_TPM2B_ATTEST("fake_quoted_data");
  const trunks::TPMT_SIGNATURE kFakeSignature = {
      .sig_alg = trunks::TPM_ALG_ECDSA,
      .signature.ecdsa.signature_r =
          trunks::Make_TPM2B_ECC_PARAMETER("fake_quote_r"),
      .signature.ecdsa.signature_s =
          trunks::Make_TPM2B_ECC_PARAMETER("fake_quote_s"),
  };

  auto load_key_result = LoadFakeECCKey(kFakeKeyHandle);
  ASSERT_OK(load_key_result);
  const ScopedKey& fake_key = load_key_result.value();

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kNonZeroPcr), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyName(kFakeKeyHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeKeyName), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpm(),
              QuoteSync(kFakeKeyHandle, kFakeKeyName, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeQuotedStruct),
                      SetArgPointee<6>(kFakeSignature),
                      Return(TPM_RC_SUCCESS)));

  auto result = backend_->GetAttestationTpm2().Quote(kFakeDeviceConfigs,
                                                     fake_key.GetKey());
  ASSERT_OK(result);
  ASSERT_TRUE(result->has_quoted_pcr_value());
  EXPECT_EQ(result->quoted_pcr_value(), kNonZeroPcr);
  ASSERT_TRUE(result->has_quoted_data());
  EXPECT_EQ(result->quoted_data(), "fake_quoted_data");
  ASSERT_TRUE(result->has_quote());
  EXPECT_NE(result->quote().find("fake_quote_r"), std::string::npos);
  EXPECT_NE(result->quote().find("fake_quote_s"), std::string::npos);
  EXPECT_FALSE(result->has_pcr_source_hint());
}

TEST_F(BackendAttestationTpm2Test, QuoteDeviceModel) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kDeviceModel};
  const std::string kNonZeroPcr(SHA256_DIGEST_LENGTH, 'X');
  const std::string kFakeKeyName = "fake_key_name";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPM2B_ATTEST kFakeQuotedStruct =
      trunks::Make_TPM2B_ATTEST("fake_quoted_data");
  const trunks::TPMT_SIGNATURE kFakeSignature = {
      .sig_alg = trunks::TPM_ALG_RSASSA,
      .signature.rsassa.sig = trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_quote"),
  };
  proxy_->GetFakeCrossystem().VbSetSystemPropertyString("hwid",
                                                        "fake_pcr_source_hint");

  auto load_key_result = LoadFakeRSAKey(kFakeKeyHandle);
  ASSERT_OK(load_key_result);
  const ScopedKey& fake_key = load_key_result.value();

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kNonZeroPcr), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyName(kFakeKeyHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeKeyName), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpm(),
              QuoteSync(kFakeKeyHandle, kFakeKeyName, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeQuotedStruct),
                      SetArgPointee<6>(kFakeSignature),
                      Return(TPM_RC_SUCCESS)));

  auto result = backend_->GetAttestationTpm2().Quote(kFakeDeviceConfigs,
                                                     fake_key.GetKey());
  ASSERT_OK(result);
  ASSERT_TRUE(result->has_quoted_pcr_value());
  EXPECT_EQ(result->quoted_pcr_value(), kNonZeroPcr);
  ASSERT_TRUE(result->has_quoted_data());
  EXPECT_EQ(result->quoted_data(), "fake_quoted_data");
  ASSERT_TRUE(result->has_quote());
  EXPECT_NE(result->quote().find("fake_quote"), std::string::npos);
  ASSERT_TRUE(result->has_pcr_source_hint());
  EXPECT_EQ(result->pcr_source_hint(), "fake_pcr_source_hint");
}

TEST_F(BackendAttestationTpm2Test, QuoteMultipleDeviceConfigs) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode, DeviceConfig::kCurrentUser};
  const std::string kFakeKeyName = "fake_key_name";
  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPM2B_ATTEST kFakeQuotedStruct =
      trunks::Make_TPM2B_ATTEST("fake_quoted_data");
  const trunks::TPMT_SIGNATURE kFakeSignature = {
      .sig_alg = trunks::TPM_ALG_RSASSA,
      .signature.rsassa.sig = trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_quote"),
  };

  auto load_key_result = LoadFakeRSAKey(kFakeKeyHandle);
  ASSERT_OK(load_key_result);
  const ScopedKey& fake_key = load_key_result.value();

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyName(kFakeKeyHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeKeyName), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpm(),
              QuoteSync(kFakeKeyHandle, kFakeKeyName, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(kFakeQuotedStruct),
                      SetArgPointee<6>(kFakeSignature),
                      Return(TPM_RC_SUCCESS)));

  auto result = backend_->GetAttestationTpm2().Quote(kFakeDeviceConfigs,
                                                     fake_key.GetKey());
  ASSERT_OK(result);
  EXPECT_FALSE(result->has_quoted_pcr_value());
  ASSERT_TRUE(result->has_quoted_data());
  EXPECT_EQ(result->quoted_data(), "fake_quoted_data");
  ASSERT_TRUE(result->has_quote());
  EXPECT_NE(result->quote().find("fake_quote"), std::string::npos);
  EXPECT_FALSE(result->has_pcr_source_hint());
}

TEST_F(BackendAttestationTpm2Test, QuoteFailure) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode};
  const std::string kNonZeroPcr(SHA256_DIGEST_LENGTH, 'X');
  const std::string kFakeKeyName = "fake_key_name";
  const uint32_t kFakeKeyHandle = 0x1337;

  auto load_key_result = LoadFakeRSAKey(kFakeKeyHandle);
  ASSERT_OK(load_key_result);
  const ScopedKey& fake_key = load_key_result.value();

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ReadPCR(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(kNonZeroPcr), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyName(kFakeKeyHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakeKeyName), Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpm(),
              QuoteSync(kFakeKeyHandle, kFakeKeyName, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  auto result = backend_->GetAttestationTpm2().Quote(kFakeDeviceConfigs,
                                                     fake_key.GetKey());
  ASSERT_NOT_OK(result);
}

TEST_F(BackendAttestationTpm2Test, IsQuoted) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode};

  auto pcr_selection_result =
      backend_->GetConfigTpm2().ToPcrSelection(kFakeDeviceConfigs);
  ASSERT_OK(pcr_selection_result);
  trunks::TPMS_PCR_SELECTION pcr_selection = pcr_selection_result.value();

  const trunks::TPMS_ATTEST fake_attest = {
      .magic = trunks::TPM_GENERATED_VALUE,
      .type = trunks::TPM_ST_ATTEST_QUOTE,
      .attested = {.quote = {.pcr_select = {
                                 .count = 1,
                                 .pcr_selections = {pcr_selection},
                             }}}};

  std::string serialized_fake_attest;
  EXPECT_EQ(trunks::Serialize_TPMS_ATTEST(fake_attest, &serialized_fake_attest),
            TPM_RC_SUCCESS);

  attestation::Quote fake_quote;
  fake_quote.set_quoted_data(serialized_fake_attest);

  auto is_quoted_result =
      backend_->GetAttestationTpm2().IsQuoted(kFakeDeviceConfigs, fake_quote);
  ASSERT_OK(is_quoted_result);
  EXPECT_TRUE(is_quoted_result.value());
}

TEST_F(BackendAttestationTpm2Test, IsQuotedWrontDeviceConfigs) {
  const DeviceConfigs kExpectedDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode};
  const DeviceConfigs kQuotedDeviceConfigs =
      DeviceConfigs{DeviceConfig::kDeviceModel};

  auto pcr_selection_result =
      backend_->GetConfigTpm2().ToPcrSelection(kQuotedDeviceConfigs);
  ASSERT_OK(pcr_selection_result);
  trunks::TPMS_PCR_SELECTION pcr_selection = pcr_selection_result.value();

  const trunks::TPMS_ATTEST fake_attest = {
      .magic = trunks::TPM_GENERATED_VALUE,
      .type = trunks::TPM_ST_ATTEST_QUOTE,
      .attested = {.quote = {.pcr_select = {
                                 .count = 1,
                                 .pcr_selections = {pcr_selection},
                             }}}};

  std::string serialized_fake_attest;
  EXPECT_EQ(trunks::Serialize_TPMS_ATTEST(fake_attest, &serialized_fake_attest),
            TPM_RC_SUCCESS);

  attestation::Quote fake_quote;
  fake_quote.set_quoted_data(serialized_fake_attest);

  auto is_quoted_result = backend_->GetAttestationTpm2().IsQuoted(
      kExpectedDeviceConfigs, fake_quote);
  ASSERT_OK(is_quoted_result);
  EXPECT_FALSE(is_quoted_result.value());
}

TEST_F(BackendAttestationTpm2Test, IsQuotedWrongFormat) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode};

  attestation::Quote fake_quote;
  fake_quote.set_quoted_data("");

  auto is_quoted_result =
      backend_->GetAttestationTpm2().IsQuoted(kFakeDeviceConfigs, fake_quote);
  ASSERT_NOT_OK(is_quoted_result);
}

}  // namespace hwsec
