// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <utility>

#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/big_num_util.h>
#include <libhwsec-foundation/crypto/elliptic_curve.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include "libhwsec/backend/tpm1/backend_test_base.h"
#include "libhwsec/overalls/mock_overalls.h"

using hwsec_foundation::SecureBlobToBigNum;
using hwsec_foundation::Sha256;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::Args;
using testing::DoAll;
using testing::ElementsAreArray;
using testing::NiceMock;
using testing::Return;
using testing::SaveArg;
using testing::SetArgPointee;
using tpm_manager::TpmManagerStatus;

namespace hwsec {

using BackendRecoveryCryptoTpm1Test = BackendTpm1TestBase;

TEST_F(BackendRecoveryCryptoTpm1Test, GenerateKeyAuthValue) {
  auto result = backend_->GetRecoveryCryptoTpm1().GenerateKeyAuthValue();

  ASSERT_OK(result);
  ASSERT_TRUE(result.value().has_value());
  EXPECT_FALSE(result.value().value().empty());
}

TEST_F(BackendRecoveryCryptoTpm1Test, EncryptEccPrivateKey) {
  brillo::SecureBlob auth_value("auth_value");
  std::string current_user = "current_user";
  brillo::Blob encrypted_own_priv_key =
      brillo::BlobFromString("encrypted_own_priv_key");
  brillo::Blob extended_pcr_bound_own_priv_key =
      brillo::BlobFromString("extended_pcr_bound_own_priv_key");

  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  ASSERT_TRUE(ec_256.has_value());

  crypto::ScopedEC_KEY destination_share_key_pair =
      ec_256->GenerateKey(context.get());

  const uint32_t kFakeEncHandle = 0x1337;
  const uint32_t kFakePcrHandle = 0x7331;
  const TSS_HPOLICY kFakeHPolicy = 0x94123;

  SetupSrk();

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_PCRS,
                                        TSS_PCRS_STRUCT_INFO, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakePcrHandle), Return(TPM_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<3>(kFakePcrHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_PcrComposite_SetPcrValue(kFakePcrHandle, _, _, _))
      .WillOnce(Return(TPM_SUCCESS))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_ENCDATA,
                                TSS_ENCDATA_SEAL, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeEncHandle), Return(TPM_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeEncHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetPolicyObject(kDefaultTpm, TSS_POLICY_USAGE, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeHPolicy), Return(TPM_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeHPolicy), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_SetSecret(kFakeHPolicy, TSS_SECRET_MODE_PLAIN, _, _))
      .With(Args<3, 2>(ElementsAreArray(auth_value)))
      .WillOnce(Return(TPM_SUCCESS))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakeHPolicy, kFakeEncHandle))
      .WillOnce(Return(TPM_SUCCESS))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Data_Seal(kFakeEncHandle, kDefaultSrkHandle, _, _, kFakePcrHandle))
      .WillOnce(Return(TPM_SUCCESS))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeEncHandle, TSS_TSPATTRIB_ENCDATA_BLOB,
                                 TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(encrypted_own_priv_key.size()),
                      SetArgPointee<4>(encrypted_own_priv_key.data()),
                      Return(TPM_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<3>(extended_pcr_bound_own_priv_key.size()),
                      SetArgPointee<4>(extended_pcr_bound_own_priv_key.data()),
                      Return(TPM_SUCCESS)));

  hwsec::EncryptEccPrivateKeyRequest encrypt_request_destination_share{
      .ec = ec_256.value(),
      .own_key_pair = std::move(destination_share_key_pair),
      .auth_value = auth_value,
      .current_user = current_user,
  };

  auto result = backend_->GetRecoveryCryptoTpm1().EncryptEccPrivateKey(
      std::move(encrypt_request_destination_share));

  ASSERT_OK(result);
  EXPECT_EQ(result->encrypted_own_priv_key, encrypted_own_priv_key);
  EXPECT_EQ(result->extended_pcr_bound_own_priv_key,
            extended_pcr_bound_own_priv_key);
}

TEST_F(BackendRecoveryCryptoTpm1Test, EncryptEccPrivateKeyNoAuth) {
  std::string current_user = "current_user";

  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  ASSERT_TRUE(ec_256.has_value());

  crypto::ScopedEC_KEY destination_share_key_pair =
      ec_256->GenerateKey(context.get());

  hwsec::EncryptEccPrivateKeyRequest encrypt_request_destination_share{
      .ec = ec_256.value(),
      .own_key_pair = std::move(destination_share_key_pair),
      .auth_value = std::nullopt,
      .current_user = current_user,
  };

  auto result = backend_->GetRecoveryCryptoTpm1().EncryptEccPrivateKey(
      std::move(encrypt_request_destination_share));

  ASSERT_OK(result);
  EXPECT_FALSE(result->encrypted_own_priv_key.empty());
  EXPECT_TRUE(result->extended_pcr_bound_own_priv_key.empty());
}

TEST_F(BackendRecoveryCryptoTpm1Test, EncryptEccPrivateKeyNoKeyPair) {
  brillo::SecureBlob auth_value("auth_value");
  std::string current_user = "current_user";

  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  ASSERT_TRUE(ec_256.has_value());

  hwsec::EncryptEccPrivateKeyRequest encrypt_request_destination_share{
      .ec = ec_256.value(),
      .own_key_pair = nullptr,
      .auth_value = auth_value,
      .current_user = current_user,
  };

  auto result = backend_->GetRecoveryCryptoTpm1().EncryptEccPrivateKey(
      std::move(encrypt_request_destination_share));

  ASSERT_NOT_OK(result);
}

TEST_F(BackendRecoveryCryptoTpm1Test, GenerateDiffieHellmanSharedSecret) {
  brillo::SecureBlob auth_value("auth_value");
  brillo::Blob enc_priv_key = brillo::BlobFromString("enc_priv_key");
  brillo::Blob ext_enc_priv_key = brillo::BlobFromString("ext_enc_priv_key");
  brillo::SecureBlob unencrypted_own_priv_key("unencrypted_own_priv_key");
  brillo::Blob empty_pcr(SHA_DIGEST_LENGTH, 0);

  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  ASSERT_TRUE(ec_256.has_value());

  crypto::ScopedEC_KEY others_key_pair = ec_256->GenerateKey(context.get());
  ASSERT_NE(others_key_pair, nullptr);

  const EC_POINT* others_pub_key_ptr =
      EC_KEY_get0_public_key(others_key_pair.get());
  ASSERT_NE(others_pub_key_ptr, nullptr);

  crypto::ScopedEC_POINT others_pub_key(
      EC_POINT_dup(others_pub_key_ptr, ec_256->GetGroup()));
  ASSERT_NE(others_pub_key, nullptr);

  EXPECT_CALL(proxy_->GetMockOveralls(), Ospi_TPM_PcrRead(kDefaultTpm, _, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(empty_pcr.size()),
                      SetArgPointee<3>(empty_pcr.data()), Return(TPM_SUCCESS)));

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
      .With(Args<3, 2>(ElementsAreArray(auth_value)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Policy_AssignToObject(kFakeHPolicy, kFakeEncHandle))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribData(kFakeEncHandle, TSS_TSPATTRIB_ENCDATA_BLOB,
                                 TSS_TSPATTRIB_ENCDATABLOB_BLOB, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Data_Unseal(kFakeEncHandle, kDefaultSrkHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(unencrypted_own_priv_key.size()),
                      SetArgPointee<3>(unencrypted_own_priv_key.data()),
                      Return(TPM_SUCCESS)));

  hwsec::GenerateDhSharedSecretRequest decrypt_request_destination_share{
      .ec = ec_256.value(),
      .encrypted_own_priv_key = enc_priv_key,
      .extended_pcr_bound_own_priv_key = ext_enc_priv_key,
      .auth_value = auth_value,
      .current_user = "obfuscated_username",
      .others_pub_point = std::move(others_pub_key),
  };

  auto result =
      backend_->GetRecoveryCryptoTpm1().GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share));

  ASSERT_OK(result);
  EXPECT_NE(result.value(), nullptr);
}

TEST_F(BackendRecoveryCryptoTpm1Test, GenerateDiffieHellmanSharedSecretNoAuth) {
  brillo::Blob enc_priv_key = brillo::BlobFromString("enc_priv_key");
  brillo::Blob ext_enc_priv_key = brillo::BlobFromString("ext_enc_priv_key");

  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  ASSERT_TRUE(ec_256.has_value());

  crypto::ScopedEC_KEY others_key_pair = ec_256->GenerateKey(context.get());
  ASSERT_NE(others_key_pair, nullptr);

  const EC_POINT* others_pub_key_ptr =
      EC_KEY_get0_public_key(others_key_pair.get());
  ASSERT_NE(others_pub_key_ptr, nullptr);

  crypto::ScopedEC_POINT others_pub_key(
      EC_POINT_dup(others_pub_key_ptr, ec_256->GetGroup()));
  ASSERT_NE(others_pub_key, nullptr);

  hwsec::GenerateDhSharedSecretRequest decrypt_request_destination_share{
      .ec = ec_256.value(),
      .encrypted_own_priv_key = enc_priv_key,
      .extended_pcr_bound_own_priv_key = ext_enc_priv_key,
      .auth_value = std::nullopt,
      .current_user = "obfuscated_username",
      .others_pub_point = std::move(others_pub_key),
  };

  auto result =
      backend_->GetRecoveryCryptoTpm1().GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share));

  ASSERT_OK(result);
  EXPECT_NE(result.value(), nullptr);
}

TEST_F(BackendRecoveryCryptoTpm1Test,
       GenerateDiffieHellmanSharedSecretNoPubPoint) {
  brillo::Blob enc_priv_key = brillo::BlobFromString("enc_priv_key");
  brillo::Blob ext_enc_priv_key = brillo::BlobFromString("ext_enc_priv_key");

  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  ASSERT_TRUE(ec_256.has_value());

  hwsec::GenerateDhSharedSecretRequest decrypt_request_destination_share{
      .ec = ec_256.value(),
      .encrypted_own_priv_key = enc_priv_key,
      .extended_pcr_bound_own_priv_key = ext_enc_priv_key,
      .auth_value = std::nullopt,
      .current_user = "obfuscated_username",
      .others_pub_point = nullptr,
  };

  auto result =
      backend_->GetRecoveryCryptoTpm1().GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share));

  EXPECT_THAT(result, NotOk());
}

TEST_F(BackendRecoveryCryptoTpm1Test, GenerateRsaKeyPair) {
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");

  const uint32_t kFakeKeyHandle = 0x1337;
  constexpr uint8_t kFakeParms[] = {0xde, 0xad, 0xbe, 0xef, 0x12,
                                    0x34, 0x56, 0x78, 0x90};
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

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_RSAKEY, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_SetAttribUint32(kFakeKeyHandle, TSS_TSPATTRIB_KEY_INFO,
                                   TSS_TSPATTRIB_KEYINFO_SIGSCHEME, _))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_CreateKey(kFakeKeyHandle, kDefaultSrkHandle, 0))
      .WillOnce(Return(TPM_SUCCESS));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_LoadKey(kFakeKeyHandle, kDefaultSrkHandle))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob key_blob = kFakeKeyBlob;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_GetAttribData(kFakeKeyHandle, TSS_TSPATTRIB_KEY_BLOB,
                                 TSS_TSPATTRIB_KEYBLOB_BLOB, _, _))
      .WillOnce(DoAll(SetArgPointee<3>(key_blob.size()),
                      SetArgPointee<4>(key_blob.data()), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(fake_pubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(), Orspi_UnloadBlob_PUBKEY_s(_, _, _, _))
      .With(Args<1, 2>(ElementsAreArray(fake_pubkey)))
      .WillOnce([&](uint64_t* offset, auto&&, auto&&, TPM_PUBKEY* tpm_pubkey) {
        *offset = fake_pubkey.size();
        uint8_t* parms_ptr = static_cast<uint8_t*>(malloc(sizeof(kFakeParms)));
        memcpy(parms_ptr, kFakeParms, sizeof(kFakeParms));
        uint8_t* key_ptr = static_cast<uint8_t*>(malloc(sizeof(kFakeModulus)));
        memcpy(key_ptr, kFakeModulus, sizeof(kFakeModulus));
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
                    .keyLength = static_cast<uint32_t>(sizeof(kFakeModulus)),
                    .key = key_ptr,
                },
        };
        return TPM_SUCCESS;
      });

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Orspi_UnloadBlob_RSA_KEY_PARMS_s(_, _, _, _))
      .With(Args<1, 2>(ElementsAreArray(kFakeParms)))
      .WillOnce(DoAll(SetArgPointee<0>(sizeof(kFakeParms)),
                      SetArgPointee<3>(TPM_RSA_KEY_PARMS{
                          .keyLength = 0,
                          .numPrimes = 0,
                          .exponentSize = 0,
                          .exponent = nullptr,
                      }),
                      Return(TPM_SUCCESS)));

  auto result = backend_->GetRecoveryCryptoTpm1().GenerateRsaKeyPair();

  ASSERT_OK(result);
  ASSERT_TRUE(result.value().has_value());
  EXPECT_EQ(result.value()->encrypted_rsa_private_key, kFakeKeyBlob);
  EXPECT_FALSE(result.value()->rsa_public_key_spki_der.empty());
}

TEST_F(BackendRecoveryCryptoTpm1Test, SignRequestPayload) {
  const brillo::Blob kFakeKeyBlob = brillo::BlobFromString("fake_key_blob");
  const brillo::Blob kFakePubkey = brillo::BlobFromString("fake_pubkey");
  const uint32_t kFakeKeyHandle = 0x1337;
  const uint32_t kFakeHashHandle = 0x7331;
  const brillo::Blob kFakeData = brillo::BlobFromString("fake_data");
  const brillo::Blob kFakeSignature = brillo::BlobFromString("fake_signature");

  SetupSrk();

  EXPECT_CALL(
      proxy_->GetMockOveralls(),
      Ospi_Context_LoadKeyByBlob(kDefaultContext, kDefaultSrkHandle, _, _, _))
      .With(Args<3, 2>(ElementsAreArray(kFakeKeyBlob)))
      .WillOnce(DoAll(SetArgPointee<4>(kFakeKeyHandle), Return(TPM_SUCCESS)));

  brillo::Blob fake_pubkey = kFakePubkey;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Key_GetPubKey(kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<1>(kFakePubkey.size()),
                      SetArgPointee<2>(fake_pubkey.data()),
                      Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Context_CreateObject(kDefaultContext, TSS_OBJECT_TYPE_HASH,
                                        TSS_HASH_OTHER, _))
      .WillOnce(DoAll(SetArgPointee<3>(kFakeHashHandle), Return(TPM_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Hash_SetHashValue(kFakeHashHandle, _, _))
      .WillOnce(Return(TPM_SUCCESS));

  brillo::Blob signature = kFakeSignature;
  EXPECT_CALL(proxy_->GetMockOveralls(),
              Ospi_Hash_Sign(kFakeHashHandle, kFakeKeyHandle, _, _))
      .WillOnce(DoAll(SetArgPointee<2>(signature.size()),
                      SetArgPointee<3>(signature.data()), Return(TPM_SUCCESS)));

  auto result = backend_->GetRecoveryCryptoTpm1().SignRequestPayload(
      kFakeKeyBlob, kFakeData);

  ASSERT_OK(result);
  ASSERT_TRUE(result.value().has_value());
  EXPECT_EQ(result.value().value(), kFakeSignature);
}

}  // namespace hwsec
