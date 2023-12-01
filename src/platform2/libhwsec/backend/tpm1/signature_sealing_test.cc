// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <openssl/rsa.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"
#include "libhwsec/overalls/mock_overalls.h"
#include "libhwsec/structures/signature_sealed_data_test_utils.h"

using hwsec_foundation::Sha1;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::AnyNumber;
using testing::Args;
using testing::AtLeast;
using testing::AtMost;
using testing::DoAll;
using testing::ElementsAreArray;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;

namespace hwsec {

namespace {

using Algorithm = Backend::SignatureSealing::Algorithm;

constexpr uint8_t kTpmRsaOaepLabel[] = {'T', 'C', 'P', 'A'};
constexpr int kMigratedCmkPrivateKeyRestPartSizeBytes = 112;
constexpr int kTpmMigrateAsymkeyBlobSize =
    sizeof(TPM_PAYLOAD_TYPE) /* for payload */ +
    SHA_DIGEST_LENGTH /* for usageAuth.authdata */ +
    SHA_DIGEST_LENGTH /* for pubDataDigest.digest */ +
    sizeof(uint32_t) /* for partPrivKeyLen */ +
    kMigratedCmkPrivateKeyRestPartSizeBytes /* for *partPrivKey */;
constexpr uint8_t kFakeParms[] = {0xde, 0xad, 0xbe, 0xef, 0x12,
                                  0x34, 0x56, 0x78, 0x90};
constexpr uint8_t kFakeOneOfPrime[] = {
    0xd7, 0xb6, 0x16, 0xb8, 0xd5, 0x99, 0x38, 0x1e, 0x66, 0xbd, 0x5a, 0x7b,
    0xb9, 0x92, 0xbe, 0x5a, 0xa2, 0xe6, 0xab, 0x64, 0x28, 0x22, 0x39, 0x56,
    0x65, 0x59, 0x91, 0x93, 0x00, 0x92, 0x0c, 0x53, 0x7f, 0x9e, 0x5e, 0x44,
    0xec, 0xb9, 0xd7, 0x57, 0xd0, 0x9b, 0x95, 0x9a, 0xbd, 0xda, 0xbc, 0x80,
    0xee, 0x71, 0x9b, 0xb8, 0x63, 0x1c, 0x36, 0xcf, 0xf5, 0x41, 0xfe, 0x0c,
    0xfb, 0x18, 0xee, 0x3c, 0x77, 0x3f, 0x10, 0xed, 0x51, 0x66, 0x94, 0x47,
    0xc5, 0x54, 0x70, 0x91, 0x44, 0xaa, 0x85, 0x66, 0x8a, 0x87, 0x23, 0xdf,
    0xdf, 0x47, 0xb2, 0x06, 0x34, 0xa9, 0x38, 0xb8, 0xfd, 0x3a, 0xaa, 0xa2,
    0xa4, 0x76, 0xca, 0xa7, 0xf6, 0x21, 0x32, 0xfe, 0xa2, 0xee, 0x10, 0x1e,
    0xcd, 0x49, 0xf5, 0xc4, 0x75, 0xb0, 0x2d, 0x58, 0x30, 0x93, 0xa3, 0x3d,
    0x17, 0x12, 0xde, 0xc2, 0x13, 0x0b, 0xbb, 0x5d,
};
constexpr uint8_t kFakeModulus[] = {
    0x00, 0xb1, 0x51, 0x8b, 0x94, 0x6a, 0xa1, 0x66, 0x91, 0xc5, 0x5a, 0xe5,
    0x9a, 0x8e, 0x33, 0x61, 0x04, 0x72, 0xf4, 0x4c, 0x28, 0x01, 0x01, 0x68,
    0x49, 0x2b, 0xcb, 0xba, 0x91, 0x11, 0xb8, 0xb0, 0x3d, 0x13, 0xb9, 0xf2,
    0x48, 0x40, 0x03, 0xe5, 0x9e, 0x57, 0x6e, 0xc9, 0xa2, 0xee, 0x12, 0x02,
    0x81, 0xde, 0x47, 0xff, 0x2f, 0xfc, 0x18, 0x71, 0xcf, 0x1a, 0xf6, 0xa7,
    0x13, 0x7c, 0x7d, 0x30, 0x3f, 0x40, 0xa2, 0x05, 0xed, 0x7d, 0x3a, 0x2f,
    0xcc, 0xbd, 0xd3, 0xd9, 0x1a, 0x76, 0xd1, 0xec, 0xd5, 0x42, 0xdb, 0x1d,
    0x64, 0x5e, 0x66, 0x00, 0x04, 0x75, 0x49, 0xb7, 0x40, 0x4d, 0xae, 0x8f,
    0xbd, 0x8b, 0x81, 0x8a, 0x34, 0xd8, 0xb9, 0x4d, 0xd2, 0xfe, 0xc9, 0x08,
    0x16, 0x6c, 0x32, 0x77, 0x2b, 0xad, 0x21, 0xa5, 0xaa, 0x3f, 0x00, 0xcf,
    0x19, 0x0a, 0x4e, 0xc2, 0x9b, 0x01, 0xef, 0x60, 0x60, 0x88, 0x33, 0x1e,
    0x62, 0xd7, 0x22, 0x56, 0x7b, 0xb1, 0x26, 0xd1, 0xe4, 0x4f, 0x0c, 0xfc,
    0xfc, 0xe7, 0x1f, 0x56, 0xef, 0x6c, 0x6a, 0xa4, 0x2f, 0xa2, 0x62, 0x62,
    0x2a, 0x89, 0xd2, 0x5c, 0x3f, 0x96, 0xc9, 0x7c, 0x54, 0x5f, 0xd6, 0xe2,
    0xa1, 0xa0, 0x59, 0xef, 0x57, 0xc5, 0xb2, 0xa8, 0x80, 0x04, 0xde, 0x29,
    0x14, 0x19, 0x9a, 0x0d, 0x49, 0x09, 0xd7, 0xbb, 0x9c, 0xc9, 0x15, 0x7a,
    0x33, 0x8a, 0x35, 0x14, 0x01, 0x4a, 0x65, 0x39, 0x8c, 0x68, 0x73, 0x91,
    0x8c, 0x70, 0xa7, 0x10, 0x7a, 0x3e, 0xff, 0xd6, 0x1b, 0xa7, 0x29, 0xad,
    0x35, 0x12, 0xeb, 0x0c, 0x26, 0xd5, 0x36, 0xa5, 0xfb, 0xab, 0x42, 0x7b,
    0xeb, 0xc9, 0x45, 0x3c, 0x6d, 0x69, 0x32, 0x36, 0xd0, 0x43, 0xf3, 0xc3,
    0x2d, 0x0a, 0xcd, 0x31, 0xf0, 0xea, 0xf3, 0x44, 0xa2, 0x00, 0x83, 0xf5,
    0x93, 0x57, 0x49, 0xd8, 0xf5,
};

brillo::Blob BuildMsaCompositeDigest(const brillo::Blob& msa_pubkey_digest) {
  // Build the structure.
  DCHECK_EQ(TPM_SHA1_160_HASH_LEN, msa_pubkey_digest.size());
  TPM_DIGEST digest;
  memcpy(digest.digest, msa_pubkey_digest.data(), msa_pubkey_digest.size());
  TPM_MSA_COMPOSITE msa_composite{
      .MSAlist = 1,
      .migAuthDigest = &digest,
  };
  // Serialize the structure.
  uint64_t serializing_offset = 0;
  Trspi_LoadBlob_MSA_COMPOSITE(&serializing_offset, nullptr, &msa_composite);
  brillo::Blob msa_composite_blob(serializing_offset);
  serializing_offset = 0;
  Trspi_LoadBlob_MSA_COMPOSITE(&serializing_offset, msa_composite_blob.data(),
                               &msa_composite);
  return Sha1(msa_composite_blob);
}

bool GenerateRsaKey(int key_size_bits,
                    crypto::ScopedEVP_PKEY* pkey,
                    brillo::Blob* key_spki_der) {
  crypto::ScopedEVP_PKEY_CTX pkey_context(
      EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr));
  if (!pkey_context)
    return false;
  if (EVP_PKEY_keygen_init(pkey_context.get()) <= 0)
    return false;
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_context.get(), key_size_bits) <=
      0) {
    return false;
  }
  EVP_PKEY* pkey_raw = nullptr;
  if (EVP_PKEY_keygen(pkey_context.get(), &pkey_raw) <= 0)
    return false;
  pkey->reset(pkey_raw);
  // Obtain the DER-encoded Subject Public Key Info.
  const int key_spki_der_length = i2d_PUBKEY(pkey->get(), nullptr);
  if (key_spki_der_length < 0)
    return false;
  key_spki_der->resize(key_spki_der_length);
  unsigned char* key_spki_der_buffer = key_spki_der->data();
  return i2d_PUBKEY(pkey->get(), &key_spki_der_buffer) == key_spki_der->size();
}

}  // namespace

class BackendSignatureSealingTpm1Test : public BackendTpm1TestBase {
 protected:
  BackendSignatureSealingTpm1Test()
      : current_user_("username"),
        unsealed_data_("secret data"),
        key_algorithms_({
            Algorithm::kRsassaPkcs1V15Sha1,
        }),
        operation_policy_setting_({
            OperationPolicySetting{
                .device_config_settings =
                    DeviceConfigSettings{
                        .current_user =
                            DeviceConfigSettings::CurrentUserSetting{
                                .username = std::nullopt}}},
            OperationPolicySetting{
                .device_config_settings =
                    DeviceConfigSettings{
                        .current_user =
                            DeviceConfigSettings::CurrentUserSetting{
                                .username = current_user_}}},
        }),
        operation_policy_(OperationPolicy{
            .device_configs = DeviceConfigs{DeviceConfig::kCurrentUser},
        }),
        fake_pubkey_(brillo::BlobFromString("key blob")),
        ma_approval_ticket_(brillo::BlobFromString("MA approval")),
        cmk_pubkey_(brillo::BlobFromString("CMK pubkey")),
        srk_wrapped_cmk_(brillo::BlobFromString("SRK wrapped CMK")),
        auth_data_(32, 'Z'),
        fake_sealed_data1_(brillo::BlobFromString("sealed_data1")),
        fake_sealed_data2_(brillo::BlobFromString("sealed_data2")),
        pcr_value_(SHA_DIGEST_LENGTH, 0),
        mig_dest_pubkey_(
            brillo::BlobFromString("migration destination pubkey")),
        fake_challenge_response_(brillo::BlobFromString("challenge response")),
        mig_auth_blob_(brillo::BlobFromString("migration authorization")),
        cmk_mig_sign_ticket_(brillo::BlobFromString("CMK migration signature")),
        migrated_cmk_key12_(brillo::BlobFromString("migrated CMK key12")),
        migration_random_(
            2 * SHA_DIGEST_LENGTH + 1 + kTpmMigrateAsymkeyBlobSize, '\0'),
        fake_modulus_(kFakeModulus, kFakeModulus + sizeof(kFakeModulus)),
        fake_one_of_prime_(kFakeOneOfPrime,
                           kFakeOneOfPrime + sizeof(kFakeOneOfPrime)),
        oaep_label_(kTpmRsaOaepLabel,
                    kTpmRsaOaepLabel + sizeof(kTpmRsaOaepLabel)),
        zero_pcr_value_(SHA_DIGEST_LENGTH, 0),
        extended_pcr_value_(Sha1(brillo::CombineBlobs(
            {zero_pcr_value_, Sha1(brillo::BlobFromString(current_user_))}))) {
    EXPECT_TRUE(GenerateRsaKey(2048, &pkey_, &public_key_spki_der_));
  }

  StatusOr<SignatureSealedData> SetupSealing(bool all_expected = true) {
    auto generic_times = AnyNumber();
    if (all_expected) {
      generic_times = AtLeast(1);
    }

    SetupDelegate();
    SetupSrk();

    uint32_t kFakePubKeyHandle = 0x1234;
    uint32_t kMigdataHandle = 0x1235;
    uint32_t kCmkHandle = 0x1236;
    uint32_t kUsagePolicyHandle = 0x1237;
    uint32_t kMigrationPolicyHandle = 0x1238;
    uint32_t kFakeEncHandle1 = 0x13371;
    uint32_t kFakePcrHandle1 = 0x73311;
    uint32_t kFakeEncHandle2 = 0x13372;
    uint32_t kFakePcrHandle2 = 0x73312;
    TSS_HPOLICY kFakeHPolicy = 0x94123;

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(
            kDefaultContext, TSS_OBJECT_TYPE_RSAKEY,
            TSS_KEY_VOLATILE | TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048, _))
        .Times(generic_times)
        .WillOnce(
            DoAll(SetArgPointee<3>(kFakePubKeyHandle), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kFakePubKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribUint32(kFakePubKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                     TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
                                     TSS_SS_RSASSAPKCS1V15_SHA1))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetAttribData(kFakePubKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                   TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(fake_pubkey_.size()),
                        SetArgPointee<4>(fake_pubkey_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Context_CreateObject(kDefaultContext,
                                          TSS_OBJECT_TYPE_MIGDATA, 0, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kMigdataHandle), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kMigdataHandle, TSS_MIGATTRIB_AUTHORITY_DATA,
                                   TSS_MIGATTRIB_AUTHORITY_DIGEST, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_TPM_CMKApproveMA(kDefaultDelegateTpm, kMigdataHandle))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetAttribData(kMigdataHandle, TSS_MIGATTRIB_AUTHORITY_DATA,
                                   TSS_MIGATTRIB_AUTHORITY_APPROVAL_HMAC, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(ma_approval_ticket_.size()),
                        SetArgPointee<4>(ma_approval_ticket_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(
            kDefaultContext, TSS_OBJECT_TYPE_RSAKEY,
            TSS_KEY_STRUCT_KEY12 | TSS_KEY_VOLATILE | TSS_KEY_TYPE_STORAGE |
                TSS_KEY_AUTHORIZATION | TSS_KEY_MIGRATABLE |
                TSS_KEY_CERTIFIED_MIGRATABLE | TSS_KEY_SIZE_2048,
            _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kCmkHandle), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kCmkHandle, TSS_TSPATTRIB_KEY_CMKINFO,
                                   TSS_TSPATTRIB_KEYINFO_CMK_MA_DIGEST, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kCmkHandle, TSS_TSPATTRIB_KEY_CMKINFO,
                                   TSS_TSPATTRIB_KEYINFO_CMK_MA_APPROVAL, _, _))
        .With(Args<4, 3>(ElementsAreArray(ma_approval_ticket_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_POLICY,
                                  TSS_POLICY_USAGE, _))
        .Times(generic_times)
        .WillOnce(
            DoAll(SetArgPointee<3>(kUsagePolicyHandle), Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Policy_SetSecret(kUsagePolicyHandle, TSS_SECRET_MODE_PLAIN, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Policy_AssignToObject(kUsagePolicyHandle, kCmkHandle))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_POLICY,
                                  TSS_POLICY_MIGRATION, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kMigrationPolicyHandle),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Policy_SetSecret(kMigrationPolicyHandle,
                                      TSS_SECRET_MODE_PLAIN, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Policy_AssignToObject(kMigrationPolicyHandle, kCmkHandle))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Key_CreateKey(kCmkHandle, kDefaultSrkHandle, 0))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetAttribData(kCmkHandle, TSS_TSPATTRIB_KEY_BLOB,
                                   TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(cmk_pubkey_.size()),
                        SetArgPointee<4>(cmk_pubkey_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetAttribData(kCmkHandle, TSS_TSPATTRIB_KEY_BLOB,
                                   TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(srk_wrapped_cmk_.size()),
                        SetArgPointee<4>(srk_wrapped_cmk_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_TPM_GetRandom(kDefaultTpm, 32, _))
        .Times(generic_times)
        .WillOnce(
            DoAll(SetArgPointee<2>(auth_data_.data()), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Orspi_UnloadBlob_PUBKEY_s(_, _, _, _))
        .With(Args<1, 2>(ElementsAreArray(cmk_pubkey_)))
        .Times(generic_times)
        .WillOnce([&](uint64_t* offset, auto&&, auto&&,
                      TPM_PUBKEY* tpm_pubkey) {
          *offset = cmk_pubkey_.size();
          uint8_t* parms_ptr =
              static_cast<uint8_t*>(malloc(sizeof(kFakeParms)));
          memcpy(parms_ptr, kFakeParms, sizeof(kFakeParms));
          uint8_t* key_ptr =
              static_cast<uint8_t*>(malloc(fake_modulus_.size()));
          memcpy(key_ptr, fake_modulus_.data(), fake_modulus_.size());
          *tpm_pubkey = TPM_PUBKEY{
              .algorithmParms =
                  TPM_KEY_PARMS{
                      .algorithmID = TPM_ALG_RSA,
                      .encScheme = TPM_ES_NONE,
                      .sigScheme = TPM_SS_NONE,
                      .parmSize = sizeof(kFakeParms),
                      .parms = parms_ptr,
                  },
              .pubKey =
                  TPM_STORE_PUBKEY{
                      .keyLength = static_cast<uint32_t>(fake_modulus_.size()),
                      .key = key_ptr,
                  },
          };
          return TPM_SUCCESS;
        });

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Orspi_UnloadBlob_RSA_KEY_PARMS_s(_, _, _, _))
        .With(Args<1, 2>(ElementsAreArray(kFakeParms)))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<0>(sizeof(kFakeParms)),
                        SetArgPointee<3>(TPM_RSA_KEY_PARMS{
                            .keyLength = 0,
                            .numPrimes = 0,
                            .exponentSize = 0,
                            .exponent = nullptr,
                        }),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_PCRS,
                                          TSS_PCRS_STRUCT_INFO, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kFakePcrHandle1), Return(TPM_SUCCESS)))
        .WillOnce(
            DoAll(SetArgPointee<3>(kFakePcrHandle2), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_PcrComposite_SetPcrValue(kFakePcrHandle1, _, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_PcrComposite_SetPcrValue(kFakePcrHandle2, _, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_ENCDATA,
                                  TSS_ENCDATA_SEAL, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kFakeEncHandle1), Return(TPM_SUCCESS)))
        .WillOnce(
            DoAll(SetArgPointee<3>(kFakeEncHandle2), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetPolicyObject(kDefaultTpm, TSS_POLICY_USAGE, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<2>(kFakeHPolicy), Return(TPM_SUCCESS)))
        .WillOnce(DoAll(SetArgPointee<2>(kFakeHPolicy), Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Policy_SetSecret(kFakeHPolicy, TSS_SECRET_MODE_PLAIN, _, _))
        .With(Args<3, 2>(ElementsAreArray(auth_data_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS))
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Policy_AssignToObject(kFakeHPolicy, kFakeEncHandle1))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Policy_AssignToObject(kFakeHPolicy, kFakeEncHandle2))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Data_Seal(kFakeEncHandle1, kDefaultSrkHandle, _, _,
                               kFakePcrHandle1))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Data_Seal(kFakeEncHandle2, kDefaultSrkHandle, _, _,
                               kFakePcrHandle2))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetAttribData(kFakeEncHandle1, TSS_TSPATTRIB_ENCDATA_BLOB,
                                   TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(fake_sealed_data1_.size()),
                        SetArgPointee<4>(fake_sealed_data1_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetAttribData(kFakeEncHandle2, TSS_TSPATTRIB_ENCDATA_BLOB,
                                   TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(fake_sealed_data2_.size()),
                        SetArgPointee<4>(fake_sealed_data2_.data()),
                        Return(TPM_SUCCESS)));

    return backend_->GetSignatureSealingTpm1().Seal(
        operation_policy_setting_, unsealed_data_, public_key_spki_der_,
        key_algorithms_);
  }

  StatusOr<Backend::SignatureSealing::ChallengeResult> SetupChallenge(
      const SignatureSealedData& sealed_data, bool all_expected = true) {
    auto generic_times = AnyNumber();
    if (all_expected) {
      generic_times = AtLeast(1);
    }
    uint32_t kFakePubKeyHandle = 0x1234;
    uint32_t kFakeMigDestPubKeyHandle = 0x1239;

    SetupDelegate();

    EXPECT_CALL(proxy_->GetMockOveralls(), Ospi_TPM_PcrRead(_, _, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<2>(pcr_value_.size()),
                        SetArgPointee<3>(pcr_value_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(
            kDefaultContext, TSS_OBJECT_TYPE_RSAKEY,
            TSS_KEY_VOLATILE | TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048, _))
        .Times(generic_times)
        .WillOnce(
            DoAll(SetArgPointee<3>(kFakePubKeyHandle), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kFakePubKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribUint32(kFakePubKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                     TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
                                     TSS_SS_RSASSAPKCS1V15_SHA1))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetAttribData(kFakePubKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                   TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(fake_pubkey_.size()),
                        SetArgPointee<4>(fake_pubkey_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(
            kDefaultContext, TSS_OBJECT_TYPE_RSAKEY,
            TSS_KEY_VOLATILE | TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kFakeMigDestPubKeyHandle),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_SetAttribData(kFakeMigDestPubKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                           TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, _, _))
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_SetAttribUint32(kFakeMigDestPubKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                             TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                             TSS_ES_RSAESOAEP_SHA1_MGF1))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_GetAttribData(kFakeMigDestPubKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                           TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(mig_dest_pubkey_.size()),
                        SetArgPointee<4>(mig_dest_pubkey_.data()),
                        Return(TPM_SUCCESS)));

    return backend_->GetSignatureSealingTpm1().Challenge(
        operation_policy_, sealed_data, public_key_spki_der_, key_algorithms_);
  }

  StatusOr<brillo::SecureBlob> SetupUnseal(
      Backend::SignatureSealing::ChallengeID challenge,
      bool all_expected = true) {
    auto generic_times = AnyNumber();
    if (all_expected) {
      generic_times = AtLeast(1);
    }

    uint32_t kFakePubKeyHandle = 0x1234;
    uint32_t kMigdataHandle = 0x1235;
    uint32_t kCmkHandle = 0x1236;
    uint32_t kMigdataHandle2 = 0x12352;
    uint32_t kFakeMigDestPubKeyHandle = 0x1239;
    uint32_t kFakeEncHandle = 0x1337;
    TSS_HPOLICY kFakeHPolicy = 0x94123;

    SetupDelegate();

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(
            kDefaultContext, TSS_OBJECT_TYPE_RSAKEY,
            TSS_KEY_VOLATILE | TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_2048, _))
        .Times(generic_times)
        .WillOnce(
            DoAll(SetArgPointee<3>(kFakePubKeyHandle), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kFakePubKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribUint32(kFakePubKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                     TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
                                     TSS_SS_RSASSAPKCS1V15_SHA1))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(
            kDefaultContext, TSS_OBJECT_TYPE_RSAKEY,
            TSS_KEY_VOLATILE | TSS_KEY_TYPE_STORAGE | TSS_KEY_SIZE_2048, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kFakeMigDestPubKeyHandle),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_SetAttribData(kFakeMigDestPubKeyHandle, TSS_TSPATTRIB_RSAKEY_INFO,
                           TSS_TSPATTRIB_KEYINFO_RSA_MODULUS, _, _))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_SetAttribUint32(kFakeMigDestPubKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                             TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                             TSS_ES_RSAESOAEP_SHA1_MGF1))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_TPM_AuthorizeMigrationTicket(
                    kDefaultDelegateTpm, kFakeMigDestPubKeyHandle,
                    TSS_MS_RESTRICT_APPROVE_DOUBLE, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(mig_auth_blob_.size()),
                        SetArgPointee<4>(mig_auth_blob_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Context_CreateObject(kDefaultContext,
                                          TSS_OBJECT_TYPE_MIGDATA, 0, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kMigdataHandle), Return(TPM_SUCCESS)))
        .WillOnce(
            DoAll(SetArgPointee<3>(kMigdataHandle2), Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_SetAttribData(kMigdataHandle, TSS_MIGATTRIB_MIGRATIONBLOB,
                           TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(mig_dest_pubkey_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kMigdataHandle, TSS_MIGATTRIB_MIGRATIONBLOB,
                                   TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(cmk_pubkey_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_SetAttribData(kMigdataHandle, TSS_MIGATTRIB_MIGRATIONBLOB,
                           TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(fake_pubkey_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kMigdataHandle, TSS_MIGATTRIB_TICKET_DATA,
                                   TSS_MIGATTRIB_TICKET_SIG_VALUE, _, _))
        .With(Args<4, 3>(ElementsAreArray(fake_challenge_response_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_TPM_CMKCreateTicket(kDefaultDelegateTpm, kFakePubKeyHandle,
                                         kMigdataHandle))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetAttribData(kMigdataHandle, TSS_MIGATTRIB_TICKET_DATA,
                                   TSS_MIGATTRIB_TICKET_SIG_TICKET, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(cmk_mig_sign_ticket_.size()),
                        SetArgPointee<4>(cmk_mig_sign_ticket_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Context_CreateObject(kDefaultContext,
                                          TSS_OBJECT_TYPE_RSAKEY, 0, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kCmkHandle), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kCmkHandle, TSS_TSPATTRIB_KEY_BLOB,
                                   TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(srk_wrapped_cmk_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_SetAttribData(kMigdataHandle2, TSS_MIGATTRIB_MIGRATIONBLOB,
                           TSS_MIGATTRIB_MIG_DESTINATION_PUBKEY_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(mig_dest_pubkey_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kMigdataHandle2, TSS_MIGATTRIB_MIGRATIONBLOB,
                                   TSS_MIGATTRIB_MIG_SOURCE_PUBKEY_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(cmk_pubkey_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_SetAttribData(kMigdataHandle2, TSS_MIGATTRIB_MIGRATIONBLOB,
                           TSS_MIGATTRIB_MIG_AUTHORITY_PUBKEY_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(fake_pubkey_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kMigdataHandle2, TSS_MIGATTRIB_MIGRATIONBLOB,
                                   TSS_MIGATTRIB_MIG_MSALIST_PUBKEY_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(fake_pubkey_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kMigdataHandle2,
                                   TSS_MIGATTRIB_MIGRATIONTICKET, 0, _, _))
        .With(Args<4, 3>(ElementsAreArray(mig_auth_blob_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kMigdataHandle2, TSS_MIGATTRIB_TICKET_DATA,
                                   TSS_MIGATTRIB_TICKET_SIG_TICKET, _, _))
        .With(Args<4, 3>(ElementsAreArray(cmk_mig_sign_ticket_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Key_CMKCreateBlob(kCmkHandle, kDefaultSrkHandle,
                                       kMigdataHandle2, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(migration_random_.size()),
                        SetArgPointee<4>(migration_random_.data()),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetAttribData(kMigdataHandle2, TSS_MIGATTRIB_MIGRATIONBLOB,
                                   TSS_MIGATTRIB_MIG_XOR_BLOB, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(migrated_cmk_key12_.size()),
                        SetArgPointee<4>(migrated_cmk_key12_.data()),
                        Return(TPM_SUCCESS)));

    brillo::Blob secret(migration_random_.size(), '\0');
    brillo::Blob padded(256);
    RSA_padding_add_PKCS1_OAEP(padded.data(), padded.size(), secret.data(),
                               secret.size(), oaep_label_.data(),
                               oaep_label_.size());
    brillo::Blob key12_encdata(256);
    RSA* rsa = backend_->GetSignatureSealingTpm1()
                   .get_current_challenge_data_for_test()
                   .value()
                   .migration_destination_rsa.get();
    RSA_public_encrypt(padded.size(), padded.data(), key12_encdata.data(), rsa,
                       RSA_NO_PADDING);

    EXPECT_CALL(proxy_->GetMockOveralls(), Orspi_UnloadBlob_KEY12_s(_, _, _, _))
        .With(Args<1, 2>(ElementsAreArray(migrated_cmk_key12_)))
        .Times(generic_times)
        .WillOnce([&](uint64_t* offset, auto&&, auto&&, TPM_KEY12* tpm_key12) {
          *offset = migrated_cmk_key12_.size();
          uint8_t* encdata_ptr =
              static_cast<uint8_t*>(malloc(key12_encdata.size()));
          memcpy(encdata_ptr, key12_encdata.data(), key12_encdata.size());
          *tpm_key12 = TPM_KEY12{
              .tag = TPM_TAG_KEY12,
              .fill = 123,
              .keyUsage = TPM_KEY_MIGRATE,
              .keyFlags = TPM_VOLATILE | TPM_MIGRATABLE,
              .authDataUsage = TPM_AUTH_NEVER,
              .algorithmParms =
                  TPM_KEY_PARMS{
                      .algorithmID = TPM_ALG_RSA,
                      .encScheme = TPM_ES_NONE,
                      .sigScheme = TPM_SS_NONE,
                      .parmSize = 0,
                      .parms = nullptr,
                  },
              .PCRInfoSize = 0,
              .PCRInfo = nullptr,
              .pubKey =
                  TPM_STORE_PUBKEY{
                      .keyLength = 0,
                      .key = nullptr,
                  },
              .encSize = static_cast<uint32_t>(key12_encdata.size()),
              .encData = encdata_ptr,
          };
          return TPM_SUCCESS;
        });

    brillo::Blob protection_key_pubkey_digest = Sha1(fake_pubkey_);
    brillo::Blob msa_composite_digest =
        BuildMsaCompositeDigest(protection_key_pubkey_digest);
    brillo::Blob cmk_pubkey_digest = Sha1(cmk_pubkey_);
    brillo::Blob tpm_migrate_asymkey_oaep_label_blob =
        brillo::CombineBlobs({msa_composite_digest, cmk_pubkey_digest});

    CHECK_EQ(fake_one_of_prime_.size(), 128);

    brillo::Blob message = brillo::CombineBlobs(
        {brillo::Blob({TPM_PT_CMK_MIGRATE}), brillo::Blob(SHA_DIGEST_LENGTH),
         brillo::Blob(SHA_DIGEST_LENGTH),
         brillo::Blob({0, 0, 0, kMigratedCmkPrivateKeyRestPartSizeBytes}),
         brillo::Blob(fake_one_of_prime_.begin() + 16,
                      fake_one_of_prime_.begin() + 128)});
    EXPECT_EQ(message.size(), kTpmMigrateAsymkeyBlobSize);

    brillo::Blob seed =
        brillo::CombineBlobs({brillo::Blob({0, 0, 0, 128}),
                              brillo::Blob(fake_one_of_prime_.begin(),
                                           fake_one_of_prime_.begin() + 16)});
    EXPECT_EQ(seed.size(), SHA_DIGEST_LENGTH);

    brillo::Blob padded_message =
        brillo::CombineBlobs({Sha1(tpm_migrate_asymkey_oaep_label_blob),
                              brillo::Blob(1, 1), message});

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Orspi_MGF1(TSS_HASH_SHA1, _, _, seed.size(), _))
        .With(Args<2, 1>(ElementsAreArray(brillo::Blob(
            SHA_DIGEST_LENGTH + 1 + kTpmMigrateAsymkeyBlobSize, '\0'))))
        .Times(generic_times)
        .WillOnce([&](auto&&, auto&&, auto&&, auto&&, uint8_t* ptr) {
          for (size_t i = 0; i < seed.size(); i++) {
            ptr[i] = seed[i];
          }
          return TPM_SUCCESS;
        });

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Orspi_MGF1(TSS_HASH_SHA1, _, _, padded_message.size(), _))
        .With(Args<2, 1>(ElementsAreArray(seed)))
        .Times(generic_times)
        .WillOnce([&](auto&&, auto&&, auto&&, auto&&, uint8_t* ptr) {
          for (size_t i = 0; i < padded_message.size(); i++) {
            ptr[i] = padded_message[i];
          }
          return TPM_SUCCESS;
        });

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Orspi_UnloadBlob_PUBKEY_s(_, _, _, _))
        .With(Args<1, 2>(ElementsAreArray(cmk_pubkey_)))
        .Times(generic_times)
        .WillOnce([&](uint64_t* offset, auto&&, auto&&,
                      TPM_PUBKEY* tpm_pubkey) {
          *offset = cmk_pubkey_.size();
          uint8_t* parms_ptr =
              static_cast<uint8_t*>(malloc(sizeof(kFakeParms)));
          memcpy(parms_ptr, kFakeParms, sizeof(kFakeParms));
          uint8_t* key_ptr =
              static_cast<uint8_t*>(malloc(fake_modulus_.size()));
          memcpy(key_ptr, fake_modulus_.data(), fake_modulus_.size());
          *tpm_pubkey = TPM_PUBKEY{
              .algorithmParms =
                  TPM_KEY_PARMS{
                      .algorithmID = TPM_ALG_RSA,
                      .encScheme = TPM_ES_NONE,
                      .sigScheme = TPM_SS_NONE,
                      .parmSize = sizeof(kFakeParms),
                      .parms = parms_ptr,
                  },
              .pubKey =
                  TPM_STORE_PUBKEY{
                      .keyLength = static_cast<uint32_t>(fake_modulus_.size()),
                      .key = key_ptr,
                  },
          };
          return TPM_SUCCESS;
        });

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Orspi_UnloadBlob_RSA_KEY_PARMS_s(_, _, _, _))
        .With(Args<1, 2>(ElementsAreArray(kFakeParms)))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<0>(sizeof(kFakeParms)),
                        SetArgPointee<3>(TPM_RSA_KEY_PARMS{
                            .keyLength = 0,
                            .numPrimes = 0,
                            .exponentSize = 0,
                            .exponent = nullptr,
                        }),
                        Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_ENCDATA,
                                  TSS_ENCDATA_SEAL, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<3>(kFakeEncHandle), Return(TPM_SUCCESS)));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_GetPolicyObject(kDefaultTpm, TSS_POLICY_USAGE, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<2>(kFakeHPolicy), Return(TPM_SUCCESS)));

    EXPECT_CALL(
        proxy_->GetMockOveralls(),
        Ospi_Policy_SetSecret(kFakeHPolicy, TSS_SECRET_MODE_PLAIN, _, _))
        .With(Args<3, 2>(ElementsAreArray(auth_data_)))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Policy_AssignToObject(kFakeHPolicy, kFakeEncHandle))
        .Times(generic_times)
        .WillOnce(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kFakeEncHandle, TSS_TSPATTRIB_ENCDATA_BLOB,
                                   TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(fake_sealed_data1_)))
        .WillRepeatedly(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_SetAttribData(kFakeEncHandle, TSS_TSPATTRIB_ENCDATA_BLOB,
                                   TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
        .With(Args<4, 3>(ElementsAreArray(fake_sealed_data2_)))
        .WillRepeatedly(Return(TPM_SUCCESS));

    EXPECT_CALL(proxy_->GetMockOveralls(),
                Ospi_Data_Unseal(kFakeEncHandle, kDefaultSrkHandle, _, _))
        .Times(generic_times)
        .WillOnce(DoAll(SetArgPointee<2>(unsealed_data_.size()),
                        SetArgPointee<3>(unsealed_data_.data()),
                        Return(TPM_SUCCESS)));

    return backend_->GetSignatureSealingTpm1().Unseal(challenge,
                                                      fake_challenge_response_);
  }

  // Default parameters.
  std::string current_user_;
  brillo::SecureBlob unsealed_data_;
  crypto::ScopedEVP_PKEY pkey_;
  brillo::Blob public_key_spki_der_;
  std::vector<Algorithm> key_algorithms_;
  std::vector<OperationPolicySetting> operation_policy_setting_;
  OperationPolicy operation_policy_;
  brillo::Blob fake_pubkey_;
  brillo::Blob ma_approval_ticket_;
  brillo::Blob cmk_pubkey_;
  brillo::Blob srk_wrapped_cmk_;
  brillo::SecureBlob auth_data_;
  brillo::Blob fake_sealed_data1_;
  brillo::Blob fake_sealed_data2_;
  brillo::Blob pcr_value_;
  brillo::Blob mig_dest_pubkey_;
  brillo::Blob fake_challenge_response_;
  brillo::Blob mig_auth_blob_;
  brillo::Blob cmk_mig_sign_ticket_;
  brillo::Blob migrated_cmk_key12_;
  brillo::Blob migration_random_;
  brillo::Blob fake_modulus_;
  brillo::Blob fake_one_of_prime_;
  brillo::Blob oaep_label_;
  brillo::Blob zero_pcr_value_;
  brillo::Blob extended_pcr_value_;
};

TEST_F(BackendSignatureSealingTpm1Test, SealChallengeUnseal) {
  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);
  ASSERT_TRUE(std::holds_alternative<Tpm12CertifiedMigratableKeyData>(
      seal_result.value()));
  SignatureSealedData expected_seal_result = Tpm12CertifiedMigratableKeyData{
      .public_key_spki_der = public_key_spki_der_,
      .srk_wrapped_cmk = srk_wrapped_cmk_,
      .cmk_pubkey = cmk_pubkey_,
      // cmk_wrapped_auth_data generated from randomized data (RsaOaepEncrypt),
      // use the seal result directly.
      .cmk_wrapped_auth_data =
          std::get<Tpm12CertifiedMigratableKeyData>(seal_result.value())
              .cmk_wrapped_auth_data,
      .pcr_bound_items =
          {
              Tpm12PcrBoundItem{
                  .pcr_values =
                      {
                          Tpm12PcrValue{
                              .pcr_index = kCurrentUserPcrTpm1,
                              .pcr_value = zero_pcr_value_,
                          },
                      },
                  .bound_secret = fake_sealed_data1_,
              },
              Tpm12PcrBoundItem{
                  .pcr_values =
                      {
                          Tpm12PcrValue{
                              .pcr_index = kCurrentUserPcrTpm1,
                              .pcr_value = extended_pcr_value_,
                          },
                      },
                  .bound_secret = fake_sealed_data2_,
              },
          },
  };
  EXPECT_EQ(seal_result.value(), expected_seal_result);

  StatusOr<Backend::SignatureSealing::ChallengeResult> challenge_result =
      SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  EXPECT_EQ(challenge_result->algorithm, Algorithm::kRsassaPkcs1V15Sha1);

  brillo::Blob protection_key_pubkey_digest = Sha1(fake_pubkey_);
  brillo::Blob migration_destination_key_pubkey_digest = Sha1(mig_dest_pubkey_);
  brillo::Blob cmk_pubkey_digest = Sha1(cmk_pubkey_);
  brillo::Blob challenge_value = brillo::CombineBlobs(
      {protection_key_pubkey_digest, migration_destination_key_pubkey_digest,
       cmk_pubkey_digest});

  EXPECT_EQ(challenge_result->challenge, challenge_value);

  EXPECT_THAT(SetupUnseal(challenge_result->challenge_id),
              IsOkAndHolds(unsealed_data_));
}

TEST_F(BackendSignatureSealingTpm1Test, SealChallengeUserPcr) {
  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);
  ASSERT_TRUE(std::holds_alternative<Tpm12CertifiedMigratableKeyData>(
      seal_result.value()));
  SignatureSealedData expected_seal_result = Tpm12CertifiedMigratableKeyData{
      .public_key_spki_der = public_key_spki_der_,
      .srk_wrapped_cmk = srk_wrapped_cmk_,
      .cmk_pubkey = cmk_pubkey_,
      // cmk_wrapped_auth_data generated from randomized data (RsaOaepEncrypt),
      // use the seal result directly.
      .cmk_wrapped_auth_data =
          std::get<Tpm12CertifiedMigratableKeyData>(seal_result.value())
              .cmk_wrapped_auth_data,
      .pcr_bound_items =
          {
              Tpm12PcrBoundItem{
                  .pcr_values =
                      {
                          Tpm12PcrValue{
                              .pcr_index = kCurrentUserPcrTpm1,
                              .pcr_value = zero_pcr_value_,
                          },
                      },
                  .bound_secret = fake_sealed_data1_,
              },
              Tpm12PcrBoundItem{
                  .pcr_values =
                      {
                          Tpm12PcrValue{
                              .pcr_index = kCurrentUserPcrTpm1,
                              .pcr_value = extended_pcr_value_,
                          },
                      },
                  .bound_secret = fake_sealed_data2_,
              },
          },
  };
  EXPECT_EQ(seal_result.value(), expected_seal_result);

  pcr_value_ = extended_pcr_value_;

  StatusOr<Backend::SignatureSealing::ChallengeResult> challenge_result =
      SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  EXPECT_EQ(challenge_result->algorithm, Algorithm::kRsassaPkcs1V15Sha1);

  brillo::Blob protection_key_pubkey_digest = Sha1(fake_pubkey_);
  brillo::Blob migration_destination_key_pubkey_digest = Sha1(mig_dest_pubkey_);
  brillo::Blob cmk_pubkey_digest = Sha1(cmk_pubkey_);
  brillo::Blob challenge_value = brillo::CombineBlobs(
      {protection_key_pubkey_digest, migration_destination_key_pubkey_digest,
       cmk_pubkey_digest});

  EXPECT_EQ(challenge_result->challenge, challenge_value);

  EXPECT_THAT(SetupUnseal(challenge_result->challenge_id),
              IsOkAndHolds(unsealed_data_));
}

TEST_F(BackendSignatureSealingTpm1Test, SealChallengeLegacyFormat) {
  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);
  ASSERT_TRUE(std::holds_alternative<Tpm12CertifiedMigratableKeyData>(
      seal_result.value()));

  ASSERT_EQ(2, std::get<Tpm12CertifiedMigratableKeyData>(seal_result.value())
                   .pcr_bound_items.size());
  ASSERT_EQ(1, std::get<Tpm12CertifiedMigratableKeyData>(seal_result.value())
                   .pcr_bound_items[0]
                   .pcr_values.size());
  ASSERT_EQ(1, std::get<Tpm12CertifiedMigratableKeyData>(seal_result.value())
                   .pcr_bound_items[1]
                   .pcr_values.size());

  // Clear the pcr_value to simulate the legacy format.
  std::get<Tpm12CertifiedMigratableKeyData>(seal_result.value())
      .pcr_bound_items[0]
      .pcr_values[0]
      .pcr_value = brillo::Blob();
  std::get<Tpm12CertifiedMigratableKeyData>(seal_result.value())
      .pcr_bound_items[1]
      .pcr_values[0]
      .pcr_value = brillo::Blob();

  StatusOr<Backend::SignatureSealing::ChallengeResult> challenge_result =
      SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  EXPECT_EQ(challenge_result->algorithm, Algorithm::kRsassaPkcs1V15Sha1);

  brillo::Blob protection_key_pubkey_digest = Sha1(fake_pubkey_);
  brillo::Blob migration_destination_key_pubkey_digest = Sha1(mig_dest_pubkey_);
  brillo::Blob cmk_pubkey_digest = Sha1(cmk_pubkey_);
  brillo::Blob challenge_value = brillo::CombineBlobs(
      {protection_key_pubkey_digest, migration_destination_key_pubkey_digest,
       cmk_pubkey_digest});

  EXPECT_EQ(challenge_result->challenge, challenge_value);

  EXPECT_THAT(SetupUnseal(challenge_result->challenge_id),
              IsOkAndHolds(unsealed_data_));

  // Check again with extended PCR.
  pcr_value_ = extended_pcr_value_;

  challenge_result = SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  EXPECT_EQ(challenge_result->algorithm, Algorithm::kRsassaPkcs1V15Sha1);

  EXPECT_EQ(challenge_result->challenge, challenge_value);

  EXPECT_THAT(SetupUnseal(challenge_result->challenge_id),
              IsOkAndHolds(unsealed_data_));
}

TEST_F(BackendSignatureSealingTpm1Test, SealWithoutSha1) {
  key_algorithms_ = std::vector<Algorithm>{
      Algorithm::kRsassaPkcs1V15Sha256,
      Algorithm::kRsassaPkcs1V15Sha384,
      Algorithm::kRsassaPkcs1V15Sha512,
  };
  StatusOr<SignatureSealedData> seal_result =
      SetupSealing(/*all_expected=*/false);
  EXPECT_FALSE(seal_result.ok());
}

TEST_F(BackendSignatureSealingTpm1Test, SealWithNoSetting) {
  operation_policy_setting_ = std::vector<OperationPolicySetting>{};
  StatusOr<SignatureSealedData> seal_result =
      SetupSealing(/*all_expected=*/false);
  EXPECT_FALSE(seal_result.ok());
}

TEST_F(BackendSignatureSealingTpm1Test, SealWrongSetting) {
  operation_policy_setting_ = std::vector<OperationPolicySetting>{
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{.current_user =
                                       DeviceConfigSettings::CurrentUserSetting{
                                           .username = std::nullopt}},
          .permission = Permission{.auth_value = brillo::SecureBlob("value")},
      },
      OperationPolicySetting{
          .device_config_settings =
              DeviceConfigSettings{.current_user =
                                       DeviceConfigSettings::CurrentUserSetting{
                                           .username = current_user_}},
      },
  };
  StatusOr<SignatureSealedData> seal_result =
      SetupSealing(/*all_expected=*/false);
  EXPECT_FALSE(seal_result.ok());
}

TEST_F(BackendSignatureSealingTpm1Test, SealBadPubKey) {
  public_key_spki_der_ = brillo::Blob(1024, '^');
  StatusOr<SignatureSealedData> seal_result =
      SetupSealing(/*all_expected=*/false);
  EXPECT_FALSE(seal_result.ok());
}

TEST_F(BackendSignatureSealingTpm1Test, SealBadModulus) {
  fake_modulus_ = brillo::Blob(38, 'T');
  StatusOr<SignatureSealedData> seal_result =
      SetupSealing(/*all_expected=*/false);
  EXPECT_FALSE(seal_result.ok());
}

TEST_F(BackendSignatureSealingTpm1Test, ChallengeWrongData) {
  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);

  // Wrong method.
  SignatureSealedData sealed_data = Tpm12CertifiedMigratableKeyData{};
  auto challenge_result = backend_->GetSignatureSealingTpm1().Challenge(
      operation_policy_, sealed_data, public_key_spki_der_, key_algorithms_);
  EXPECT_FALSE(challenge_result.ok());

  // Empty public_key_spki_der.
  sealed_data = seal_result.value();
  std::get<Tpm12CertifiedMigratableKeyData>(sealed_data).public_key_spki_der =
      brillo::Blob();
  challenge_result = backend_->GetSignatureSealingTpm1().Challenge(
      operation_policy_, sealed_data, public_key_spki_der_, key_algorithms_);
  EXPECT_FALSE(challenge_result.ok());

  // Empty srk_wrapped_cmk.
  sealed_data = seal_result.value();
  std::get<Tpm12CertifiedMigratableKeyData>(sealed_data).srk_wrapped_cmk =
      brillo::Blob();
  challenge_result = backend_->GetSignatureSealingTpm1().Challenge(
      operation_policy_, sealed_data, public_key_spki_der_, key_algorithms_);
  EXPECT_FALSE(challenge_result.ok());

  // Empty cmk_wrapped_auth_data.
  sealed_data = seal_result.value();
  std::get<Tpm12CertifiedMigratableKeyData>(sealed_data).cmk_wrapped_auth_data =
      brillo::Blob();
  challenge_result = backend_->GetSignatureSealingTpm1().Challenge(
      operation_policy_, sealed_data, public_key_spki_der_, key_algorithms_);
  EXPECT_FALSE(challenge_result.ok());

  // Empty cmk_pubkey.
  sealed_data = seal_result.value();
  std::get<Tpm12CertifiedMigratableKeyData>(sealed_data).cmk_pubkey =
      brillo::Blob();
  challenge_result = backend_->GetSignatureSealingTpm1().Challenge(
      operation_policy_, sealed_data, public_key_spki_der_, key_algorithms_);
  EXPECT_FALSE(challenge_result.ok());

  // Mismatch public_key_spki_der.
  sealed_data = seal_result.value();
  std::get<Tpm12CertifiedMigratableKeyData>(sealed_data)
      .public_key_spki_der[0] ^= 1;
  challenge_result = backend_->GetSignatureSealingTpm1().Challenge(
      operation_policy_, sealed_data, public_key_spki_der_, key_algorithms_);
  EXPECT_FALSE(challenge_result.ok());

  // Mismatch algorithm.
  challenge_result = backend_->GetSignatureSealingTpm1().Challenge(
      operation_policy_, seal_result.value(), public_key_spki_der_,
      std::vector<Algorithm>{
          Algorithm::kRsassaPkcs1V15Sha256,
          Algorithm::kRsassaPkcs1V15Sha384,
          Algorithm::kRsassaPkcs1V15Sha512,
      });
  EXPECT_FALSE(challenge_result.ok());

  // Empty PCR bound secret.
  sealed_data = seal_result.value();
  std::get<Tpm12CertifiedMigratableKeyData>(sealed_data)
      .pcr_bound_items[0]
      .bound_secret = brillo::Blob();
  std::get<Tpm12CertifiedMigratableKeyData>(sealed_data)
      .pcr_bound_items[1]
      .bound_secret = brillo::Blob();
  challenge_result = backend_->GetSignatureSealingTpm1().Challenge(
      operation_policy_, sealed_data, public_key_spki_der_, key_algorithms_);
  EXPECT_FALSE(challenge_result.ok());
}

TEST_F(BackendSignatureSealingTpm1Test, UnsealNoChallenge) {
  auto unseal_result = backend_->GetSignatureSealingTpm1().Unseal(
      static_cast<Backend::SignatureSealing::ChallengeID>(0),
      fake_challenge_response_);
  EXPECT_FALSE(unseal_result.ok());
}

TEST_F(BackendSignatureSealingTpm1Test, UnsealWrongData) {
  // No challenge.
  auto unseal_result = backend_->GetSignatureSealingTpm1().Unseal(
      static_cast<Backend::SignatureSealing::ChallengeID>(0),
      fake_challenge_response_);
  EXPECT_FALSE(unseal_result.ok());

  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);

  StatusOr<Backend::SignatureSealing::ChallengeResult> challenge_result =
      SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  // Wrong challenge ID.
  Backend::SignatureSealing::ChallengeID challenge_id =
      challenge_result->challenge_id;
  challenge_id = static_cast<Backend::SignatureSealing::ChallengeID>(
      static_cast<uint32_t>(challenge_id) + 3);
  unseal_result = backend_->GetSignatureSealingTpm1().Unseal(
      challenge_id, fake_challenge_response_);
  EXPECT_FALSE(unseal_result.ok());
}

TEST_F(BackendSignatureSealingTpm1Test, UnsealWrongModulus) {
  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);

  StatusOr<Backend::SignatureSealing::ChallengeResult> challenge_result =
      SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  fake_modulus_ = brillo::Blob(38, 'T');

  EXPECT_THAT(
      SetupUnseal(challenge_result->challenge_id, /*all_expected=*/false),
      NotOk());
}

TEST_F(BackendSignatureSealingTpm1Test, UnsealWrongPrime) {
  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);

  StatusOr<Backend::SignatureSealing::ChallengeResult> challenge_result =
      SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  fake_one_of_prime_[0] ^= 1;

  EXPECT_THAT(
      SetupUnseal(challenge_result->challenge_id, /*all_expected=*/false),
      NotOk());
}

TEST_F(BackendSignatureSealingTpm1Test, UnsealWrongMigrationRandom) {
  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);

  StatusOr<Backend::SignatureSealing::ChallengeResult> challenge_result =
      SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  migration_random_ = brillo::Blob(42, '*');

  EXPECT_THAT(
      SetupUnseal(challenge_result->challenge_id, /*all_expected=*/false),
      NotOk());
}

TEST_F(BackendSignatureSealingTpm1Test, UnsealWrongOaepLabel) {
  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);

  StatusOr<Backend::SignatureSealing::ChallengeResult> challenge_result =
      SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  oaep_label_ = brillo::BlobFromString("CROS");

  EXPECT_THAT(
      SetupUnseal(challenge_result->challenge_id, /*all_expected=*/false),
      NotOk());
}

TEST_F(BackendSignatureSealingTpm1Test, UnsealWrongPolicy) {
  StatusOr<SignatureSealedData> seal_result = SetupSealing();
  ASSERT_OK(seal_result);

  operation_policy_ = OperationPolicy{
      .device_configs = DeviceConfigs{DeviceConfig::kCurrentUser},
      .permission = Permission{.auth_value = brillo::SecureBlob("value")},
  };

  StatusOr<Backend::SignatureSealing::ChallengeResult> challenge_result =
      SetupChallenge(seal_result.value());
  ASSERT_OK(challenge_result);

  EXPECT_THAT(
      SetupUnseal(challenge_result->challenge_id, /*all_expected=*/false),
      NotOk());
}

}  // namespace hwsec
