// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <openssl/sha.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"
#include "libhwsec/overalls/mock_overalls.h"
#include "libhwsec/structures/key.h"

using brillo::BlobFromString;
using brillo::BlobToString;
using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;

namespace hwsec {

class BackendAttestationTpm1Test : public BackendTpm1TestBase {
 protected:
  StatusOr<ScopedKey> LoadFakeKey(const uint32_t fake_key_handle) {
    const OperationPolicy kFakePolicy{};
    const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
    const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");

    SetupSrk();

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
        .WillOnce(
            DoAll(SetArgPointee<4>(fake_key_handle), Return(TPM_SUCCESS)));

    brillo::Blob fake_pubkey = kFakePubkey;
    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Key_GetPubKey(fake_key_handle, _, _))
        .WillOnce(DoAll(SetArgPointee<1>(fake_pubkey.size()),
                        SetArgPointee<2>(fake_pubkey.data()),
                        Return(TPM_SUCCESS)));

    return backend_->GetKeyManagementTpm1().LoadKey(
        kFakePolicy, kFakeKeyBlob, Backend::KeyManagement::LoadKeyOptions{});
  }
};

TEST_F(BackendAttestationTpm1Test, Quote) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode};
  const brillo::Blob kNonZeroPcr(SHA_DIGEST_LENGTH, 'X');
  const uint32_t kFakeKeyHandle = 0x1337;
  const std::string kFakeQuotedData = "fake_quoted_data";
  const std::string kFakeQuote = "fake_quote";
  std::string fake_quoted_data = kFakeQuotedData;
  std::string fake_quote = kFakeQuote;
  TSS_VALIDATION fake_validation = {
      .ulDataLength = static_cast<UINT32>(fake_quoted_data.size()),
      .rgbData = reinterpret_cast<unsigned char*>(fake_quoted_data.data()),
      .ulValidationDataLength = static_cast<UINT32>(fake_quote.size()),
      .rgbValidationData = reinterpret_cast<unsigned char*>(fake_quote.data()),
  };

  auto load_key_result = LoadFakeKey(kFakeKeyHandle);
  ASSERT_OK(load_key_result);
  const ScopedKey& fake_key = load_key_result.value();

  brillo::Blob non_zero_pcr = kNonZeroPcr;
  EXPECT_CALL(proxy_->GetMockOveralls(), Ospi_TPM_PcrRead(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(non_zero_pcr.size()),
                      SetArgPointee<3>(non_zero_pcr.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_TPM_Quote(_, kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(fake_validation), Return(TPM_SUCCESS)));

  auto result = backend_->GetAttestationTpm1().Quote(kFakeDeviceConfigs,
                                                     fake_key.GetKey());
  ASSERT_OK(result);
  ASSERT_TRUE(result->has_quoted_pcr_value());
  EXPECT_EQ(result->quoted_pcr_value(), BlobToString(kNonZeroPcr));
  ASSERT_TRUE(result->has_quoted_data());
  EXPECT_EQ(result->quoted_data(), "fake_quoted_data");
  ASSERT_TRUE(result->has_quote());
  EXPECT_EQ(result->quote(), "fake_quote");
  EXPECT_FALSE(result->has_pcr_source_hint());
}

TEST_F(BackendAttestationTpm1Test, QuoteDeviceModel) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kDeviceModel};
  const brillo::Blob kNonZeroPcr(SHA_DIGEST_LENGTH, 'X');
  const uint32_t kFakeKeyHandle = 0x1337;
  const std::string kFakeQuotedData = "fake_quoted_data";
  const std::string kFakeQuote = "fake_quote";
  std::string fake_quoted_data = kFakeQuotedData;
  std::string fake_quote = kFakeQuote;
  TSS_VALIDATION fake_validation = {
      .ulDataLength = static_cast<UINT32>(fake_quoted_data.size()),
      .rgbData = reinterpret_cast<unsigned char*>(fake_quoted_data.data()),
      .ulValidationDataLength = static_cast<UINT32>(fake_quote.size()),
      .rgbValidationData = reinterpret_cast<unsigned char*>(fake_quote.data()),
  };
  proxy_->GetFakeCrossystem().VbSetSystemPropertyString("hwid",
                                                        "fake_pcr_source_hint");

  auto load_key_result = LoadFakeKey(kFakeKeyHandle);
  ASSERT_OK(load_key_result);
  const ScopedKey& fake_key = load_key_result.value();

  brillo::Blob non_zero_pcr = kNonZeroPcr;
  EXPECT_CALL(proxy_->GetMockOveralls(), Ospi_TPM_PcrRead(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(non_zero_pcr.size()),
                      SetArgPointee<3>(non_zero_pcr.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_TPM_Quote(_, kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(fake_validation), Return(TPM_SUCCESS)));

  auto result = backend_->GetAttestationTpm1().Quote(kFakeDeviceConfigs,
                                                     fake_key.GetKey());
  ASSERT_OK(result);
  ASSERT_TRUE(result->has_quoted_pcr_value());
  EXPECT_EQ(result->quoted_pcr_value(), BlobToString(kNonZeroPcr));
  ASSERT_TRUE(result->has_quoted_data());
  EXPECT_EQ(result->quoted_data(), "fake_quoted_data");
  ASSERT_TRUE(result->has_quote());
  EXPECT_EQ(result->quote(), "fake_quote");
  ASSERT_TRUE(result->has_pcr_source_hint());
  EXPECT_EQ(result->pcr_source_hint(), "fake_pcr_source_hint");
}

TEST_F(BackendAttestationTpm1Test, QuoteMultipleDeviceConfigs) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode, DeviceConfig::kCurrentUser};
  const uint32_t kFakeKeyHandle = 0x1337;
  const std::string kFakeQuotedData = "fake_quoted_data";
  const std::string kFakeQuote = "fake_quote";
  std::string fake_quoted_data = kFakeQuotedData;
  std::string fake_quote = kFakeQuote;
  TSS_VALIDATION fake_validation = {
      .ulDataLength = static_cast<UINT32>(fake_quoted_data.size()),
      .rgbData = reinterpret_cast<unsigned char*>(fake_quoted_data.data()),
      .ulValidationDataLength = static_cast<UINT32>(fake_quote.size()),
      .rgbValidationData = reinterpret_cast<unsigned char*>(fake_quote.data()),
  };

  auto load_key_result = LoadFakeKey(kFakeKeyHandle);
  ASSERT_OK(load_key_result);
  const ScopedKey& fake_key = load_key_result.value();

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_TPM_Quote(_, kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(fake_validation), Return(TPM_SUCCESS)));

  auto result = backend_->GetAttestationTpm1().Quote(kFakeDeviceConfigs,
                                                     fake_key.GetKey());
  ASSERT_OK(result);
  EXPECT_FALSE(result->has_quoted_pcr_value());
  ASSERT_TRUE(result->has_quoted_data());
  EXPECT_EQ(result->quoted_data(), "fake_quoted_data");
  ASSERT_TRUE(result->has_quote());
  EXPECT_EQ(result->quote(), "fake_quote");
  EXPECT_FALSE(result->has_pcr_source_hint());
}

TEST_F(BackendAttestationTpm1Test, QuoteFailure) {
  const DeviceConfigs kFakeDeviceConfigs =
      DeviceConfigs{DeviceConfig::kBootMode};
  const brillo::Blob kNonZeroPcr(SHA_DIGEST_LENGTH, 'X');
  const uint32_t kFakeKeyHandle = 0x1337;

  auto load_key_result = LoadFakeKey(kFakeKeyHandle);
  ASSERT_OK(load_key_result);
  const ScopedKey& fake_key = load_key_result.value();

  brillo::Blob non_zero_pcr = kNonZeroPcr;
  EXPECT_CALL(proxy_->GetMockOveralls(), Ospi_TPM_PcrRead(_, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(non_zero_pcr.size()),
                      SetArgPointee<3>(non_zero_pcr.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_TPM_Quote(_, kFakeKeyHandle, _, _))
      .WillOnce(Return(TSS_E_FAIL));

  auto result = backend_->GetAttestationTpm1().Quote(kFakeDeviceConfigs,
                                                     fake_key.GetKey());
  ASSERT_NOT_OK(result);
}

}  // namespace hwsec
