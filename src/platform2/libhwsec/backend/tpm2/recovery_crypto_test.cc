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
#include <trunks/openssl_utility.h>
#include <trunks/mock_policy_session.h>
#include <trunks/mock_tpm_utility.h>

#include "libhwsec/backend/tpm2/backend_test_base.h"

using hwsec_foundation::SecureBlobToBigNum;
using hwsec_foundation::Sha256;
using hwsec_foundation::error::testing::IsOk;
using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
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

using BackendRecoveryCryptoTpm2Test = BackendTpm2TestBase;

TEST_F(BackendRecoveryCryptoTpm2Test, GenerateKeyAuthValue) {
  EXPECT_THAT(backend_->GetRecoveryCryptoTpm2().GenerateKeyAuthValue(),
              IsOkAndHolds(std::nullopt));
}

TEST_F(BackendRecoveryCryptoTpm2Test, EncryptEccPrivateKey) {
  const std::string fake_digests1 = "fake_digests1";
  const std::string fake_digests2 = "fake_digests2";
  const std::string fake_digests3 = "fake_digests3";
  const brillo::Blob encrypted_own_priv_key =
      brillo::BlobFromString("encrypted_own_priv_key");

  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  ASSERT_TRUE(ec_256.has_value());

  crypto::ScopedEC_KEY destination_share_key_pair =
      ec_256->GenerateKey(context.get());

  ASSERT_NE(destination_share_key_pair, nullptr);

  EXPECT_CALL(proxy_->GetMockTrialSession(), StartUnboundSession(false, false))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(proxy_->GetMockTrialSession(), PolicyPCR(_))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTrialSession(), GetDigest(_))
      // The intermediate digests for different policy.
      .WillOnce(DoAll(SetArgPointee<0>(fake_digests1),
                      Return(trunks::TPM_RC_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<0>(fake_digests2),
                      Return(trunks::TPM_RC_SUCCESS)))
      // The final digest that combines intermediate digests and signature.
      .WillOnce(DoAll(SetArgPointee<0>(fake_digests3),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTrialSession(),
              PolicyOR(std::vector<std::string>{fake_digests1, fake_digests2}))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              ImportECCKeyWithPolicyDigest(
                  trunks::TpmUtility::AsymmetricKeyUsage::kDecryptKey,
                  trunks::TPM_ECC_NIST_P256, _, _, _, fake_digests3, _, _))
      .WillOnce(
          DoAll(SetArgPointee<7>(brillo::BlobToString(encrypted_own_priv_key)),
                Return(trunks::TPM_RC_SUCCESS)));

  hwsec::EncryptEccPrivateKeyRequest encrypt_request_destination_share{
      .ec = ec_256.value(),
      .own_key_pair = std::move(destination_share_key_pair),
      .auth_value = std::nullopt,
      .current_user = "obfuscated_username",
  };

  auto result = backend_->GetRecoveryCryptoTpm2().EncryptEccPrivateKey(
      std::move(encrypt_request_destination_share));

  ASSERT_OK(result);
  EXPECT_EQ(result->encrypted_own_priv_key, encrypted_own_priv_key);
  EXPECT_TRUE(result->extended_pcr_bound_own_priv_key.empty());
}

TEST_F(BackendRecoveryCryptoTpm2Test, EncryptEccPrivateKeyWithAuth) {
  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  ASSERT_TRUE(ec_256.has_value());

  crypto::ScopedEC_KEY destination_share_key_pair =
      ec_256->GenerateKey(context.get());

  ASSERT_NE(destination_share_key_pair, nullptr);

  hwsec::EncryptEccPrivateKeyRequest encrypt_request_destination_share{
      .ec = ec_256.value(),
      .own_key_pair = std::move(destination_share_key_pair),
      .auth_value = brillo::SecureBlob("auth_value"),
      .current_user = "obfuscated_username",
  };

  auto result = backend_->GetRecoveryCryptoTpm2().EncryptEccPrivateKey(
      std::move(encrypt_request_destination_share));

  EXPECT_THAT(result, NotOk());
}

TEST_F(BackendRecoveryCryptoTpm2Test, EncryptEccPrivateKeyNoKeyPair) {
  hwsec_foundation::ScopedBN_CTX context =
      hwsec_foundation::CreateBigNumContext();

  std::optional<hwsec_foundation::EllipticCurve> ec_256 =
      hwsec_foundation::EllipticCurve::Create(
          hwsec_foundation::EllipticCurve::CurveType::kPrime256, context.get());

  ASSERT_TRUE(ec_256.has_value());

  hwsec::EncryptEccPrivateKeyRequest encrypt_request_destination_share{
      .ec = ec_256.value(),
      .own_key_pair = nullptr,
      .auth_value = std::nullopt,
      .current_user = "obfuscated_username",
  };

  auto result = backend_->GetRecoveryCryptoTpm2().EncryptEccPrivateKey(
      std::move(encrypt_request_destination_share));

  EXPECT_THAT(result, NotOk());
}

TEST_F(BackendRecoveryCryptoTpm2Test, GenerateDiffieHellmanSharedSecret) {
  const std::string fake_digests1 = "fake_digests1";
  const std::string fake_digests2 = "fake_digests2";
  const std::string fake_digests3 = "fake_digests3";
  const brillo::Blob enc_priv_key = brillo::BlobFromString("enc_priv_key");
  const brillo::Blob ext_enc_priv_key =
      brillo::BlobFromString("ext_enc_priv_key");

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

  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPMT_PUBLIC kFakePublic = {};

  crypto::ScopedBIGNUM private_key =
      SecureBlobToBigNum(Sha256(brillo::SecureBlob("seed")));
  crypto::ScopedEC_POINT public_point =
      ec_256->MultiplyWithGenerator(*private_key, context.get());
  trunks::TPMS_ECC_POINT ecc_point;
  trunks::OpensslToTpmEccPoint(*ec_256->GetGroup(), *public_point,
                               ec_256->AffineCoordinateSizeInBytes(),
                               &ecc_point);
  trunks::TPM2B_ECC_POINT fake_point = trunks::Make_TPM2B_ECC_POINT(ecc_point);

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              LoadKey(brillo::BlobToString(enc_priv_key), _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTrialSession(), StartUnboundSession(false, false))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(proxy_->GetMockTrialSession(), PolicyPCR(_))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTrialSession(), GetDigest(_))
      // The intermediate digests for different policy.
      .WillOnce(DoAll(SetArgPointee<0>(fake_digests1),
                      Return(trunks::TPM_RC_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<0>(fake_digests2),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ECDHZGen(kFakeKeyHandle, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(fake_point), Return(trunks::TPM_RC_SUCCESS)));

  hwsec::GenerateDhSharedSecretRequest decrypt_request_destination_share{
      .ec = ec_256.value(),
      .encrypted_own_priv_key = enc_priv_key,
      .extended_pcr_bound_own_priv_key = ext_enc_priv_key,
      .auth_value = std::nullopt,
      .current_user = "obfuscated_username",
      .others_pub_point = std::move(others_pub_key),
  };

  auto result =
      backend_->GetRecoveryCryptoTpm2().GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share));

  ASSERT_OK(result);
  EXPECT_NE(result.value(), nullptr);
}

TEST_F(BackendRecoveryCryptoTpm2Test,
       GenerateDiffieHellmanSharedSecretInvalidPoint) {
  const std::string fake_digests1 = "fake_digests1";
  const std::string fake_digests2 = "fake_digests2";
  const std::string fake_digests3 = "fake_digests3";
  const brillo::Blob enc_priv_key = brillo::BlobFromString("enc_priv_key");
  const brillo::Blob ext_enc_priv_key =
      brillo::BlobFromString("ext_enc_priv_key");

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

  const uint32_t kFakeKeyHandle = 0x1337;
  const trunks::TPMT_PUBLIC kFakePublic = {};

  trunks::TPM2B_ECC_POINT fake_point{
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

  EXPECT_CALL(proxy_->GetMockTpmUtility(),
              LoadKey(brillo::BlobToString(enc_priv_key), _, _))
      .WillOnce(DoAll(SetArgPointee<2>(kFakeKeyHandle),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(
          DoAll(SetArgPointee<1>(kFakePublic), Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTrialSession(), StartUnboundSession(false, false))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));
  EXPECT_CALL(proxy_->GetMockTrialSession(), PolicyPCR(_))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS))
      .WillOnce(Return(trunks::TPM_RC_SUCCESS));

  EXPECT_CALL(proxy_->GetMockTrialSession(), GetDigest(_))
      // The intermediate digests for different policy.
      .WillOnce(DoAll(SetArgPointee<0>(fake_digests1),
                      Return(trunks::TPM_RC_SUCCESS)))
      .WillOnce(DoAll(SetArgPointee<0>(fake_digests2),
                      Return(trunks::TPM_RC_SUCCESS)));

  EXPECT_CALL(proxy_->GetMockTpmUtility(), ECDHZGen(kFakeKeyHandle, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(fake_point), Return(trunks::TPM_RC_SUCCESS)));

  hwsec::GenerateDhSharedSecretRequest decrypt_request_destination_share{
      .ec = ec_256.value(),
      .encrypted_own_priv_key = enc_priv_key,
      .extended_pcr_bound_own_priv_key = ext_enc_priv_key,
      .auth_value = std::nullopt,
      .current_user = "obfuscated_username",
      .others_pub_point = std::move(others_pub_key),
  };

  auto result =
      backend_->GetRecoveryCryptoTpm2().GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share));

  EXPECT_THAT(result, NotOk());
}

TEST_F(BackendRecoveryCryptoTpm2Test,
       GenerateDiffieHellmanSharedSecretWithAuth) {
  const brillo::Blob enc_priv_key = brillo::BlobFromString("enc_priv_key");
  const brillo::Blob ext_enc_priv_key =
      brillo::BlobFromString("ext_enc_priv_key");

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
      .auth_value = brillo::SecureBlob("auth"),
      .current_user = "obfuscated_username",
      .others_pub_point = std::move(others_pub_key),
  };

  auto result =
      backend_->GetRecoveryCryptoTpm2().GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share));

  EXPECT_THAT(result, NotOk());
}

TEST_F(BackendRecoveryCryptoTpm2Test,
       GenerateDiffieHellmanSharedSecretNoPoint) {
  const brillo::Blob enc_priv_key = brillo::BlobFromString("enc_priv_key");
  const brillo::Blob ext_enc_priv_key =
      brillo::BlobFromString("ext_enc_priv_key");

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
      backend_->GetRecoveryCryptoTpm2().GenerateDiffieHellmanSharedSecret(
          std::move(decrypt_request_destination_share));

  EXPECT_THAT(result, NotOk());
}

TEST_F(BackendRecoveryCryptoTpm2Test, GenerateRsaKeyPair) {
  EXPECT_THAT(backend_->GetRecoveryCryptoTpm2().GenerateRsaKeyPair(),
              IsOkAndHolds(std::nullopt));
}

TEST_F(BackendRecoveryCryptoTpm2Test, SignRequestPayload) {
  EXPECT_THAT(backend_->GetRecoveryCryptoTpm2().SignRequestPayload(
                  brillo::Blob(), brillo::Blob()),
              IsOkAndHolds(std::nullopt));
}

}  // namespace hwsec
