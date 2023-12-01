// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <iterator>
#include <optional>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/task_environment.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <tpm_manager-client/tpm_manager/dbus-constants.h>
#include <tpm_manager/client/mock_tpm_manager_utility.h>
#include <trunks/mock_blob_parser.h>
#include <trunks/mock_tpm.h>
#include <trunks/mock_tpm_utility.h>
#include <trunks/trunks_factory_for_test.h>

#include "attestation/common/tpm_utility_v2.h"
#include "trunks/tpm_generated.h"

namespace {

using ::testing::_;
using ::testing::DoAll;
using ::testing::ElementsAre;
using ::testing::Ne;
using ::testing::NiceMock;
using ::testing::Optional;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::SetArgPointee;
using ::testing::WithArg;
using ::trunks::TPM_RC_FAILURE;
using ::trunks::TPM_RC_SUCCESS;

const char kDefaultPassword[] = "password";
constexpr char kNvRamData[] = "fake nvram data";

std::string HexDecode(const std::string hex) {
  std::vector<uint8_t> output;
  CHECK(base::HexStringToBytes(hex, &output));
  return std::string(reinterpret_cast<char*>(output.data()), output.size());
}

std::string GenerateFakeQuotedData(std::string const& fake_nv_data) {
  trunks::TPMS_ATTEST fake_attestation_data;
  fake_attestation_data.qualified_signer.size = trunks::UINT16(0);
  fake_attestation_data.extra_data.size = trunks::UINT16(0);
  fake_attestation_data.type = trunks::TPM_ST_ATTEST_NV;
  fake_attestation_data.attested.nv.index_name.size = 0;
  fake_attestation_data.attested.nv.nv_contents.size = fake_nv_data.size();
  memcpy(fake_attestation_data.attested.nv.nv_contents.buffer,
         fake_nv_data.data(), fake_nv_data.size());
  std::string fake_quoted_data;
  trunks::Serialize_TPMS_ATTEST(fake_attestation_data, &fake_quoted_data);

  return fake_quoted_data;
}

}  // namespace

namespace attestation {

class TpmUtilityTest : public testing::Test {
 public:
  ~TpmUtilityTest() override = default;
  void SetUp() override {
    // Setup default status data.
    tpm_status_.set_status(tpm_manager::STATUS_SUCCESS);
    tpm_status_.set_enabled(true);
    tpm_status_.set_owned(true);
    tpm_status_.mutable_local_data()->set_endorsement_password(
        kDefaultPassword);
    ON_CALL(mock_tpm_utility_, GetKeyPublicArea(_, _))
        .WillByDefault(DoAll(SetArgPointee<1>(GetValidRsaPublicKey(nullptr)),
                             Return(TPM_RC_SUCCESS)));
    // Setup trunks factory with mocks.
    trunks_factory_for_test_.set_tpm(&mock_tpm_);
    trunks_factory_for_test_.set_tpm_utility(&mock_tpm_utility_);
    trunks_factory_for_test_.set_blob_parser(&mock_blob_parser_);
    tpm_utility_.reset(new TpmUtilityV2(&mock_tpm_manager_utility_,
                                        &trunks_factory_for_test_));
    tpm_utility_->Initialize();
  }

 protected:
  trunks::TPMT_PUBLIC GetValidRsaPublicKey(
      std::string* serialized_public_area) {
    constexpr char kValidModulusHex[] =
        "961037BC12D2A298BEBF06B2D5F8C9B64B832A2237F8CF27D5F96407A6041A4D"
        "AD383CB5F88E625F412E8ACD5E9D69DF0F4FA81FCE7955829A38366CBBA5A2B1"
        "CE3B48C14B59E9F094B51F0A39155874C8DE18A0C299EBF7A88114F806BE4F25"
        "3C29A509B10E4B19E31675AFE3B2DA77077D94F43D8CE61C205781ED04D183B4"
        "C349F61B1956C64B5398A3A98FAFF17D1B3D9120C832763EDFC8F4137F6EFBEF"
        "46D8F6DE03BD00E49DEF987C10BDD5B6F8758B6A855C23C982DDA14D8F0F2B74"
        "E6DEFA7EEE5A6FC717EB0FF103CB8049F693A2C8A5039EF1F5C025DC44BD8435"
        "E8D8375DADE00E0C0F5C196E04B8483CC98B1D5B03DCD7E0048B2AB343FFC11F";

    trunks::TPMT_PUBLIC public_area = {};
    public_area.type = trunks::TPM_ALG_RSA;
    public_area.name_alg = trunks::TPM_ALG_SHA256;
    public_area.parameters.rsa_detail.key_bits = 2048;
    public_area.unique.rsa =
        trunks::Make_TPM2B_PUBLIC_KEY_RSA(HexDecode(kValidModulusHex));
    if (serialized_public_area) {
      Serialize_TPMT_PUBLIC(public_area, serialized_public_area);
    }
    return public_area;
  }

  trunks::TPMT_PUBLIC GetValidEccPublicKey(
      std::string* x, std::string* y, std::string* serialized_public_area) {
    constexpr char kValidECPointX[] =
        "06845c8f3ac8b98d0e8163d0475ad4c8be1710c9f2d39965719e3684a7b3f40b";
    constexpr char kValidECPointY[] =
        "0400e219928d45093b3d7ff3cae43468e24684454f318b83b12304d1194a3286";

    trunks::TPMT_PUBLIC public_area = {};
    std::vector<uint8_t> point_tmp_buffer;
    CHECK(base::HexStringToBytes(kValidECPointX, &point_tmp_buffer));
    CHECK_EQ(point_tmp_buffer.size(), std::size(kValidECPointX) / 2);
    public_area.unique.ecc.x.size = point_tmp_buffer.size();
    memcpy(public_area.unique.ecc.x.buffer, point_tmp_buffer.data(),
           point_tmp_buffer.size());
    if (x) {
      x->assign(point_tmp_buffer.begin(), point_tmp_buffer.end());
    }

    point_tmp_buffer.clear();
    CHECK(base::HexStringToBytes(kValidECPointY, &point_tmp_buffer));
    CHECK_EQ(point_tmp_buffer.size(), std::size(kValidECPointY) / 2);
    public_area.unique.ecc.y.size = point_tmp_buffer.size();
    memcpy(public_area.unique.ecc.y.buffer, point_tmp_buffer.data(),
           point_tmp_buffer.size());
    if (y) {
      y->assign(point_tmp_buffer.begin(), point_tmp_buffer.end());
    }

    public_area.type = trunks::TPM_ALG_ECC;
    public_area.name_alg = trunks::TPM_ALG_SHA256;
    public_area.parameters.ecc_detail.curve_id = trunks::TPM_ECC_NIST_P256;
    public_area.parameters.ecc_detail.kdf.scheme = trunks::TPM_ALG_NULL;
    public_area.parameters.ecc_detail.scheme.scheme = trunks::TPM_ALG_NULL;

    if (serialized_public_area) {
      Serialize_TPMT_PUBLIC(public_area, serialized_public_area);
    }
    return public_area;
  }

  trunks::TPMT_PUBLIC GetValidEccPublicKey(
      std::string* serialized_public_area) {
    return GetValidEccPublicKey(/*x=*/nullptr, /*y=*/nullptr,
                                serialized_public_area);
  }

  void ExpectGetTpmStatus() {
    tpm_manager::LocalData local_data;
    local_data.set_owner_password("password");
    local_data.set_endorsement_password("endorsement_password");
    EXPECT_CALL(mock_tpm_manager_utility_, GetTpmStatus(_, _, _))
        .WillOnce(DoAll(SetArgPointee<0>(true), SetArgPointee<1>(true),
                        SetArgPointee<2>(local_data), Return(true)));
  }

  tpm_manager::GetTpmStatusReply tpm_status_;

  NiceMock<tpm_manager::MockTpmManagerUtility> mock_tpm_manager_utility_;
  NiceMock<trunks::MockTpm> mock_tpm_;
  NiceMock<trunks::MockTpmUtility> mock_tpm_utility_;
  NiceMock<trunks::MockBlobParser> mock_blob_parser_;
  trunks::TrunksFactoryForTest trunks_factory_for_test_;
  std::unique_ptr<TpmUtilityV2> tpm_utility_;
  base::test::SingleThreadTaskEnvironment task_environment_;
};

TEST_F(TpmUtilityTest, GetSupportedKeyTypes) {
  EXPECT_THAT(tpm_utility_->GetSupportedKeyTypes(),
              ElementsAre(KEY_TYPE_RSA, KEY_TYPE_ECC));
}

TEST_F(TpmUtilityTest, ActivateIdentity) {
  ExpectGetTpmStatus();
  trunks::TPM2B_DIGEST fake_credential =
      trunks::Make_TPM2B_DIGEST("fake_credential");
  EXPECT_CALL(mock_tpm_, ActivateCredentialSync(_, _, _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<6>(fake_credential), Return(TPM_RC_SUCCESS)));
  std::string credential;
  EXPECT_TRUE(tpm_utility_->ActivateIdentityForTpm2(
      KEY_TYPE_RSA, "fake_identity_blob", "seed", "mac", "wrapped",
      &credential));
  EXPECT_EQ("fake_credential", credential);
}

TEST_F(TpmUtilityTest, ActivateIdentityFailLoadIdentityKey) {
  EXPECT_CALL(mock_tpm_utility_, LoadKey(_, _, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  EXPECT_CALL(mock_tpm_utility_, LoadKey("fake_identity_blob", _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string credential;
  EXPECT_FALSE(tpm_utility_->ActivateIdentityForTpm2(
      KEY_TYPE_RSA, "fake_identity_blob", "seed", "mac", "wrapped",
      &credential));
  EXPECT_TRUE(credential.empty());
}

TEST_F(TpmUtilityTest, ActivateIdentityFailLoadEndorsementKey) {
  ExpectGetTpmStatus();
  EXPECT_CALL(mock_tpm_utility_, GetEndorsementKey(_, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string credential;
  EXPECT_FALSE(tpm_utility_->ActivateIdentityForTpm2(
      KEY_TYPE_RSA, "fake_identity_blob", "seed", "mac", "wrapped",
      &credential));
  EXPECT_TRUE(credential.empty());
}

TEST_F(TpmUtilityTest, ActivateIdentityNoEndorsementPassword) {
  tpm_status_.mutable_local_data()->clear_endorsement_password();
  std::string credential;
  EXPECT_FALSE(tpm_utility_->ActivateIdentityForTpm2(
      KEY_TYPE_RSA, "fake_identity_blob", "seed", "mac", "wrapped",
      &credential));
  EXPECT_TRUE(credential.empty());
}

TEST_F(TpmUtilityTest, ActivateIdentityError) {
  ExpectGetTpmStatus();
  EXPECT_CALL(mock_tpm_, ActivateCredentialSync(_, _, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string credential;
  EXPECT_FALSE(tpm_utility_->ActivateIdentityForTpm2(
      KEY_TYPE_RSA, "fake_identity_blob", "seed", "mac", "wrapped",
      &credential));
  EXPECT_TRUE(credential.empty());
}

TEST_F(TpmUtilityTest, CreateCertifiedKeyWithRsaKey) {
  EXPECT_CALL(mock_tpm_utility_, CreateRSAKeyPair(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<8>("fake_key_blob"), Return(TPM_RC_SUCCESS)));
  trunks::TPM2B_DATA external_data;
  trunks::TPMT_SIG_SCHEME scheme;
  trunks::TPM2B_ATTEST fake_certify_info =
      trunks::Make_TPM2B_ATTEST("fake_attest");
  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_RSASSA;
  fake_signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_proof");
  EXPECT_CALL(mock_tpm_, CertifySync(_, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<4>(&external_data), SaveArg<5>(&scheme),
                      SetArgPointee<6>(fake_certify_info),
                      SetArgPointee<7>(fake_signature),
                      Return(TPM_RC_SUCCESS)));
  std::string key_blob;
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  EXPECT_TRUE(tpm_utility_->CreateCertifiedKey(
      KEY_TYPE_RSA, KEY_USAGE_SIGN, KeyRestriction::kUnrestricted,
      /*profile_hint=*/std::nullopt, "fake_identity_blob", "fake_external_data",
      &key_blob, &public_key_der, &public_key_tpm_format, &key_info, &proof));
  EXPECT_EQ("fake_key_blob", key_blob);
  EXPECT_NE("", public_key_der);
  EXPECT_NE("", public_key_tpm_format);
  EXPECT_EQ("fake_attest", key_info);
  EXPECT_NE(std::string::npos, proof.find("fake_proof"));
  EXPECT_EQ("fake_external_data", trunks::StringFrom_TPM2B_DATA(external_data));
  EXPECT_EQ(trunks::TPM_ALG_RSASSA, scheme.scheme);
  EXPECT_EQ(trunks::TPM_ALG_SHA256, scheme.details.rsassa.hash_alg);
}

TEST_F(TpmUtilityTest, CreateCertifiedKeyWithEccKey) {
  const std::string kFakeKeyBlob = "fake_key_blob";

  EXPECT_CALL(mock_tpm_utility_, CreateECCKeyPair(_, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(kFakeKeyBlob), Return(TPM_RC_SUCCESS)));

  // make sure LoadKey(created key) return ECC, RSA for AIK
  EXPECT_CALL(mock_tpm_utility_, LoadKey(_, _, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  constexpr trunks::TPM_HANDLE kFakeKeyHandle = 0x12345678;
  EXPECT_CALL(mock_tpm_utility_, LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kFakeKeyHandle), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidRsaPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidEccPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));

  // Still use RSA AIK to certified, so return the RSA signature.
  trunks::TPM2B_DATA external_data;
  trunks::TPMT_SIG_SCHEME scheme;
  trunks::TPM2B_ATTEST fake_certify_info =
      trunks::Make_TPM2B_ATTEST("fake_attest");
  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_RSASSA;
  fake_signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_proof");
  EXPECT_CALL(mock_tpm_, CertifySync(_, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<4>(&external_data), SaveArg<5>(&scheme),
                      SetArgPointee<6>(fake_certify_info),
                      SetArgPointee<7>(fake_signature),
                      Return(TPM_RC_SUCCESS)));

  std::string key_blob;
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  EXPECT_TRUE(tpm_utility_->CreateCertifiedKey(
      KEY_TYPE_ECC, KEY_USAGE_SIGN, KeyRestriction::kUnrestricted,
      /*profile_hint=*/std::nullopt, "fake_identity_blob", "fake_external_data",
      &key_blob, &public_key_der, &public_key_tpm_format, &key_info, &proof));
  EXPECT_EQ(key_blob, kFakeKeyBlob);
  EXPECT_NE(public_key_der, "");
  EXPECT_NE(public_key_tpm_format, "");
  EXPECT_EQ(key_info, "fake_attest");
  EXPECT_NE(proof.find("fake_proof"), std::string::npos);
  EXPECT_EQ(trunks::StringFrom_TPM2B_DATA(external_data), "fake_external_data");
  EXPECT_EQ(scheme.scheme, trunks::TPM_ALG_RSASSA);
  EXPECT_EQ(scheme.details.rsassa.hash_alg, trunks::TPM_ALG_SHA256);
}

TEST_F(TpmUtilityTest, CreateCertifiedKeyRestrictedECC) {
  const std::string kFakeKeyBlob = "fake_key_blob";

  EXPECT_CALL(mock_tpm_utility_,
              CreateRestrictedECCKeyPair(_, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(kFakeKeyBlob), Return(TPM_RC_SUCCESS)));

  // make sure LoadKey(created key) return ECC, RSA for AIK
  EXPECT_CALL(mock_tpm_utility_, LoadKey(_, _, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  constexpr trunks::TPM_HANDLE kFakeKeyHandle = 0x12345678;
  EXPECT_CALL(mock_tpm_utility_, LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kFakeKeyHandle), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidRsaPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidEccPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));

  // Still use RSA AIK to certified, so return the RSA signature.
  trunks::TPM2B_DATA external_data;
  trunks::TPMT_SIG_SCHEME scheme;
  trunks::TPM2B_ATTEST fake_certify_info =
      trunks::Make_TPM2B_ATTEST("fake_attest");
  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_RSASSA;
  fake_signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_proof");
  EXPECT_CALL(mock_tpm_, CertifySync(_, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<4>(&external_data), SaveArg<5>(&scheme),
                      SetArgPointee<6>(fake_certify_info),
                      SetArgPointee<7>(fake_signature),
                      Return(TPM_RC_SUCCESS)));

  std::string key_blob;
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  EXPECT_TRUE(tpm_utility_->CreateCertifiedKey(
      KEY_TYPE_ECC, KEY_USAGE_SIGN, KeyRestriction::kRestricted,
      /*profile_hint=*/std::nullopt, "fake_identity_blob", "fake_external_data",
      &key_blob, &public_key_der, &public_key_tpm_format, &key_info, &proof));
  EXPECT_EQ(key_blob, kFakeKeyBlob);
  EXPECT_NE(public_key_der, "");
  EXPECT_NE(public_key_tpm_format, "");
  EXPECT_EQ(key_info, "fake_attest");
  EXPECT_NE(proof.find("fake_proof"), std::string::npos);
  EXPECT_EQ(trunks::StringFrom_TPM2B_DATA(external_data), "fake_external_data");
  EXPECT_EQ(scheme.scheme, trunks::TPM_ALG_RSASSA);
  EXPECT_EQ(scheme.details.rsassa.hash_alg, trunks::TPM_ALG_SHA256);
}

TEST_F(TpmUtilityTest,
       CreateCertifiedKeyRestrictedECCWithPolicySetByPolicyHint) {
  const std::string kFakeKeyBlob = "fake_key_blob";

  EXPECT_CALL(mock_tpm_utility_,
              CreateRestrictedECCKeyPair(
                  _, _, _, std::string(trunks::GetEkTemplateAuthPolicy()), _, _,
                  _, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(kFakeKeyBlob), Return(TPM_RC_SUCCESS)));

  // make sure LoadKey(created key) return ECC, RSA for AIK
  EXPECT_CALL(mock_tpm_utility_, LoadKey(_, _, _))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  constexpr trunks::TPM_HANDLE kFakeKeyHandle = 0x12345678;
  EXPECT_CALL(mock_tpm_utility_, LoadKey(kFakeKeyBlob, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kFakeKeyHandle), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidRsaPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidEccPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));

  // Still use RSA AIK to certified, so return the RSA signature.
  trunks::TPM2B_DATA external_data;
  trunks::TPMT_SIG_SCHEME scheme;
  trunks::TPM2B_ATTEST fake_certify_info =
      trunks::Make_TPM2B_ATTEST("fake_attest");
  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_RSASSA;
  fake_signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_proof");
  EXPECT_CALL(mock_tpm_, CertifySync(_, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<4>(&external_data), SaveArg<5>(&scheme),
                      SetArgPointee<6>(fake_certify_info),
                      SetArgPointee<7>(fake_signature),
                      Return(TPM_RC_SUCCESS)));

  std::string key_blob;
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  EXPECT_TRUE(tpm_utility_->CreateCertifiedKey(
      KEY_TYPE_ECC, KEY_USAGE_SIGN, KeyRestriction::kRestricted,
      ENTERPRISE_VTPM_EK_CERTIFICATE, "fake_identity_blob",
      "fake_external_data", &key_blob, &public_key_der, &public_key_tpm_format,
      &key_info, &proof));
  EXPECT_EQ(key_blob, kFakeKeyBlob);
  EXPECT_NE(public_key_der, "");
  EXPECT_NE(public_key_tpm_format, "");
  EXPECT_EQ(key_info, "fake_attest");
  EXPECT_NE(proof.find("fake_proof"), std::string::npos);
  EXPECT_EQ(trunks::StringFrom_TPM2B_DATA(external_data), "fake_external_data");
  EXPECT_EQ(scheme.scheme, trunks::TPM_ALG_RSASSA);
  EXPECT_EQ(scheme.details.rsassa.hash_alg, trunks::TPM_ALG_SHA256);
}

TEST_F(TpmUtilityTest, CreateCertifiedKeyRestrictedRSANotSupported) {
  std::string key_blob;
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  EXPECT_FALSE(tpm_utility_->CreateCertifiedKey(
      KEY_TYPE_RSA, KEY_USAGE_SIGN, KeyRestriction::kRestricted,
      /*profile_hint=*/std::nullopt, "fake_identity_blob", "fake_external_data",
      &key_blob, &public_key_der, &public_key_tpm_format, &key_info, &proof));
}

TEST_F(TpmUtilityTest, CreateCertifiedKeyWithEccCertified) {
  EXPECT_CALL(mock_tpm_utility_, CreateRSAKeyPair(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<8>("fake_key_blob"), Return(TPM_RC_SUCCESS)));

  // make sure LoadKey(created key) return RSA, but ECC for AIK
  constexpr trunks::TPM_HANDLE kFakeKeyHandle = 0x87654321;
  EXPECT_CALL(mock_tpm_utility_, LoadKey("fake_key_blob", _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kFakeKeyHandle), Return(TPM_RC_SUCCESS)));

  constexpr trunks::TPM_HANDLE kFakeIdentityHandle = 0x12345678;
  EXPECT_CALL(mock_tpm_utility_, LoadKey("fake_identity_blob", _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(kFakeIdentityHandle), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(kFakeKeyHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidRsaPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(kFakeIdentityHandle, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidEccPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));

  trunks::TPM2B_DATA external_data;
  trunks::TPMT_SIG_SCHEME scheme;
  trunks::TPM2B_ATTEST fake_certify_info =
      trunks::Make_TPM2B_ATTEST("fake_attest");

  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_ECDSA;
  fake_signature.signature.ecdsa.signature_r =
      trunks::Make_TPM2B_ECC_PARAMETER("fake_proof_r");
  fake_signature.signature.ecdsa.signature_s =
      trunks::Make_TPM2B_ECC_PARAMETER("fake_proof_s");

  EXPECT_CALL(mock_tpm_, CertifySync(_, _, _, _, _, _, _, _, _))
      .WillOnce(DoAll(SaveArg<4>(&external_data), SaveArg<5>(&scheme),
                      SetArgPointee<6>(fake_certify_info),
                      SetArgPointee<7>(fake_signature),
                      Return(TPM_RC_SUCCESS)));

  std::string key_blob;
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  EXPECT_TRUE(tpm_utility_->CreateCertifiedKey(
      KEY_TYPE_RSA, KEY_USAGE_SIGN, KeyRestriction::kUnrestricted,
      /*profile_hint=*/std::nullopt, "fake_identity_blob", "fake_external_data",
      &key_blob, &public_key_der, &public_key_tpm_format, &key_info, &proof));
  EXPECT_EQ("fake_key_blob", key_blob);
  EXPECT_NE("", public_key_der);
  EXPECT_NE("", public_key_tpm_format);
  EXPECT_EQ("fake_attest", key_info);
  EXPECT_NE(proof.find("fake_proof_r"), std::string::npos);
  EXPECT_NE(proof.find("fake_proof_s"), std::string::npos);
  EXPECT_EQ("fake_external_data", trunks::StringFrom_TPM2B_DATA(external_data));
  EXPECT_EQ(trunks::TPM_ALG_ECDSA, scheme.scheme);
  EXPECT_EQ(trunks::TPM_ALG_SHA256, scheme.details.rsassa.hash_alg);
}

TEST_F(TpmUtilityTest, CreateCertifiedKeyFailCreate) {
  EXPECT_CALL(mock_tpm_utility_, CreateRSAKeyPair(_, _, _, _, _, _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  std::string key_blob;
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  EXPECT_FALSE(tpm_utility_->CreateCertifiedKey(
      KEY_TYPE_RSA, KEY_USAGE_SIGN, KeyRestriction::kUnrestricted,
      /*profile_hint=*/std::nullopt, "fake_identity_blob", "fake_external_data",
      &key_blob, &public_key_der, &public_key_tpm_format, &key_info, &proof));
  EXPECT_EQ("", key_blob);
  EXPECT_EQ("", public_key_der);
  EXPECT_EQ("", public_key_tpm_format);
}

TEST_F(TpmUtilityTest, CreateCertifiedKeyFailCertify) {
  EXPECT_CALL(mock_tpm_utility_, CreateRSAKeyPair(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<8>("fake_key_blob"), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_tpm_, CertifySync(_, _, _, _, _, _, _, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  std::string key_blob;
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string key_info;
  std::string proof;
  EXPECT_FALSE(tpm_utility_->CreateCertifiedKey(
      KEY_TYPE_RSA, KEY_USAGE_SIGN, KeyRestriction::kUnrestricted,
      /*profile_hint=*/std::nullopt, "fake_identity_blob", "fake_external_data",
      &key_blob, &public_key_der, &public_key_tpm_format, &key_info, &proof));
}

TEST_F(TpmUtilityTest, GetEndorsementPublicKey) {
  ExpectGetTpmStatus();
  std::string key;
  EXPECT_TRUE(tpm_utility_->GetEndorsementPublicKey(KEY_TYPE_RSA, &key));
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidEccPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));
  EXPECT_TRUE(tpm_utility_->GetEndorsementPublicKey(KEY_TYPE_ECC, &key));
}

TEST_F(TpmUtilityTest, GetEndorsementPublicKeyModulusSuccess) {
  EXPECT_CALL(mock_tpm_utility_, GetPublicRSAEndorsementKeyModulus(_))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  std::string key;
  EXPECT_TRUE(tpm_utility_->GetEndorsementPublicKeyModulus(KEY_TYPE_RSA, &key));
  // The key type ECC is not implemented yet.
  EXPECT_FALSE(
      tpm_utility_->GetEndorsementPublicKeyModulus(KEY_TYPE_ECC, &key));
}

TEST_F(TpmUtilityTest, GetEndorsementPublicKeyModulusNoKey) {
  EXPECT_CALL(mock_tpm_utility_, GetPublicRSAEndorsementKeyModulus(_))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  std::string key;
  EXPECT_FALSE(
      tpm_utility_->GetEndorsementPublicKeyModulus(KEY_TYPE_RSA, &key));
  EXPECT_TRUE(key.empty());
  EXPECT_FALSE(
      tpm_utility_->GetEndorsementPublicKeyModulus(KEY_TYPE_ECC, &key));
  EXPECT_TRUE(key.empty());
}

TEST_F(TpmUtilityTest, GetEndorsementPublicKeyBytesRsaSuccess) {
  EXPECT_CALL(mock_tpm_utility_, GetPublicRSAEndorsementKeyModulus(_))
      .WillRepeatedly(Return(TPM_RC_SUCCESS));
  std::string ek_bytes;
  EXPECT_TRUE(
      tpm_utility_->GetEndorsementPublicKeyBytes(KEY_TYPE_RSA, &ek_bytes));
}

TEST_F(TpmUtilityTest, GetEndorsementPublicKeyBytesRsaFailure) {
  EXPECT_CALL(mock_tpm_utility_, GetPublicRSAEndorsementKeyModulus(_))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  std::string ek_bytes;
  EXPECT_FALSE(
      tpm_utility_->GetEndorsementPublicKeyModulus(KEY_TYPE_RSA, &ek_bytes));
  EXPECT_TRUE(ek_bytes.empty());
}

TEST_F(TpmUtilityTest, GetEndorsementPublicKeyBytesEccSuccess) {
  ExpectGetTpmStatus();
  std::string x, y;
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidEccPublicKey(&x, &y, nullptr)),
                      Return(TPM_RC_SUCCESS)));
  std::string ek_bytes;
  EXPECT_TRUE(
      tpm_utility_->GetEndorsementPublicKeyBytes(KEY_TYPE_ECC, &ek_bytes));
  EXPECT_EQ(ek_bytes, x + y);
}

TEST_F(TpmUtilityTest, GetEndorsementPublicKeyBytesEccFailure) {
  ExpectGetTpmStatus();
  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(_, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string ek_bytes;
  EXPECT_FALSE(
      tpm_utility_->GetEndorsementPublicKeyBytes(KEY_TYPE_ECC, &ek_bytes));
  EXPECT_TRUE(ek_bytes.empty());
}

TEST_F(TpmUtilityTest, GetEndorsementCertificateRsa) {
  EXPECT_CALL(
      mock_tpm_manager_utility_,
      ReadSpace(trunks::kRsaEndorsementCertificateNonRealIndex, false, _))
      .WillOnce(DoAll(SetArgPointee<2>("rsa_cert"), Return(true)));
  std::string certificate;
  EXPECT_TRUE(
      tpm_utility_->GetEndorsementCertificate(KEY_TYPE_RSA, &certificate));
  EXPECT_EQ("rsa_cert", certificate);
}

TEST_F(TpmUtilityTest, GetEndorsementCertificateEcc) {
  EXPECT_CALL(
      mock_tpm_manager_utility_,
      ReadSpace(trunks::kEccEndorsementCertificateNonRealIndex, false, _))
      .WillOnce(DoAll(SetArgPointee<2>("ecc_cert"), Return(true)));
  std::string certificate;
  EXPECT_TRUE(
      tpm_utility_->GetEndorsementCertificate(KEY_TYPE_ECC, &certificate));
  EXPECT_EQ("ecc_cert", certificate);
}

TEST_F(TpmUtilityTest, GetEndorsementCertificateNoCert) {
  EXPECT_CALL(
      mock_tpm_manager_utility_,
      ReadSpace(trunks::kRsaEndorsementCertificateNonRealIndex, false, _))
      .WillOnce(Return(false));
  std::string certificate;
  EXPECT_FALSE(
      tpm_utility_->GetEndorsementCertificate(KEY_TYPE_RSA, &certificate));
}

TEST_F(TpmUtilityTest, Unbind) {
  EXPECT_CALL(mock_tpm_utility_,
              AsymmetricDecrypt(_, _, _, "fake_encrypted", _, _))
      .WillOnce(DoAll(SetArgPointee<5>("fake_data"), Return(TPM_RC_SUCCESS)));
  std::string data;
  EXPECT_TRUE(tpm_utility_->Unbind("fake_key_blob", "fake_encrypted", &data));
  EXPECT_EQ("fake_data", data);
}

TEST_F(TpmUtilityTest, UnbindFail) {
  EXPECT_CALL(mock_tpm_utility_,
              AsymmetricDecrypt(_, _, _, "fake_encrypted", _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  std::string data;
  EXPECT_FALSE(tpm_utility_->Unbind("fake_key_blob", "fake_encrypted", &data));
  EXPECT_EQ("", data);
}

TEST_F(TpmUtilityTest, SignWithRsa) {
  EXPECT_CALL(mock_tpm_utility_,
              Sign(_, trunks::TPM_ALG_RSASSA, _, "fake_to_sign", true, _, _))
      .WillOnce(
          DoAll(SetArgPointee<6>("fake_signature"), Return(TPM_RC_SUCCESS)));
  std::string signature;
  EXPECT_TRUE(tpm_utility_->Sign("fake_key_blob", "fake_to_sign", &signature));
  EXPECT_EQ("fake_signature", signature);
}

TEST_F(TpmUtilityTest, SignWithEcc) {
  // Sign() have to return a Serialized TPMT_SIGNATURE string for ECDSA
  trunks::TPMT_SIGNATURE fake_signature = {};
  fake_signature.sig_alg = trunks::TPM_ALG_ECDSA;
  fake_signature.signature.ecdsa.signature_r =
      trunks::Make_TPM2B_ECC_PARAMETER("fake_signature_r");
  fake_signature.signature.ecdsa.signature_s =
      trunks::Make_TPM2B_ECC_PARAMETER("fake_signature_s");
  std::string fake_signature_string;
  trunks::Serialize_TPMT_SIGNATURE(fake_signature, &fake_signature_string);
  EXPECT_CALL(mock_tpm_utility_,
              Sign(_, trunks::TPM_ALG_ECDSA, _, "fake_to_sign", true, _, _))
      .WillOnce(DoAll(SetArgPointee<6>(fake_signature_string),
                      Return(TPM_RC_SUCCESS)));

  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidEccPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));

  std::string signature;
  EXPECT_TRUE(tpm_utility_->Sign("fake_key_blob", "fake_to_sign", &signature));
  EXPECT_NE(signature.find("fake_signature_r"), std::string::npos);
  EXPECT_NE(signature.find("fake_signature_s"), std::string::npos);
}

TEST_F(TpmUtilityTest, SignFail) {
  EXPECT_CALL(mock_tpm_utility_, Sign(_, _, _, "fake_to_sign", true, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  std::string signature;
  EXPECT_FALSE(tpm_utility_->Sign("fake_key_blob", "fake_to_sign", &signature));
  EXPECT_EQ("", signature);
}

TEST_F(TpmUtilityTest, CreateRestrictedKeySuccessWithRsa) {
  EXPECT_CALL(mock_tpm_utility_, CreateIdentityKey(trunks::TPM_ALG_RSA, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>("fake_key_blob"), Return(TPM_RC_SUCCESS)));
  std::string expected_public_key;
  trunks::TPMT_PUBLIC public_area = GetValidRsaPublicKey(&expected_public_key);
  EXPECT_CALL(mock_blob_parser_, ParseKeyBlob("fake_key_blob", _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(trunks::Make_TPM2B_PUBLIC(public_area)),
                Return(true)));
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string private_key;
  EXPECT_TRUE(tpm_utility_->CreateRestrictedKey(
      KEY_TYPE_RSA, KEY_USAGE_SIGN, &public_key_der, &public_key_tpm_format,
      &private_key));
  EXPECT_NE("", public_key_der);
  EXPECT_EQ(expected_public_key, public_key_tpm_format);
  EXPECT_EQ("fake_key_blob", private_key);
}

TEST_F(TpmUtilityTest, CreateRestrictedKeySuccessWithEcc) {
  EXPECT_CALL(mock_tpm_utility_, CreateIdentityKey(trunks::TPM_ALG_ECC, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>("fake_key_blob"), Return(TPM_RC_SUCCESS)));
  std::string expected_public_key;
  trunks::TPMT_PUBLIC public_area = GetValidEccPublicKey(&expected_public_key);
  EXPECT_CALL(mock_blob_parser_, ParseKeyBlob("fake_key_blob", _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(trunks::Make_TPM2B_PUBLIC(public_area)),
                Return(true)));
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string private_key;
  EXPECT_TRUE(tpm_utility_->CreateRestrictedKey(
      KEY_TYPE_ECC, KEY_USAGE_SIGN, &public_key_der, &public_key_tpm_format,
      &private_key));
  EXPECT_NE("", public_key_der);
  EXPECT_EQ(expected_public_key, public_key_tpm_format);
  EXPECT_EQ("fake_key_blob", private_key);
}

TEST_F(TpmUtilityTest, CreateRestrictedKeyFail) {
  EXPECT_CALL(mock_tpm_utility_, CreateIdentityKey(trunks::TPM_ALG_RSA, _, _))
      .WillRepeatedly(Return(TPM_RC_FAILURE));
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string private_key;
  EXPECT_FALSE(tpm_utility_->CreateRestrictedKey(
      KEY_TYPE_RSA, KEY_USAGE_SIGN, &public_key_der, &public_key_tpm_format,
      &private_key));
  EXPECT_EQ("", public_key_der);
  EXPECT_EQ("", public_key_tpm_format);
  EXPECT_EQ("", private_key);
}

TEST_F(TpmUtilityTest, CreateRestrictedKeyParserFail) {
  EXPECT_CALL(mock_tpm_utility_, CreateIdentityKey(trunks::TPM_ALG_RSA, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>("fake_key_blob"), Return(TPM_RC_SUCCESS)));
  EXPECT_CALL(mock_blob_parser_, ParseKeyBlob("fake_key_blob", _, _))
      .WillRepeatedly(Return(false));
  std::string public_key_der;
  std::string public_key_tpm_format;
  std::string private_key;
  EXPECT_FALSE(tpm_utility_->CreateRestrictedKey(
      KEY_TYPE_RSA, KEY_USAGE_SIGN, &public_key_der, &public_key_tpm_format,
      &private_key));
  EXPECT_EQ("", public_key_der);
  EXPECT_EQ("", public_key_tpm_format);
}

TEST_F(TpmUtilityTest, ReadPCR) {
  EXPECT_CALL(mock_tpm_utility_, ReadPCR(5, _))
      .WillOnce(
          DoAll(SetArgPointee<1>("fake_pcr_value"), Return(TPM_RC_SUCCESS)));
  std::string value;
  EXPECT_TRUE(tpm_utility_->ReadPCR(5, &value));
  EXPECT_EQ("fake_pcr_value", value);
}

TEST_F(TpmUtilityTest, ReadPCRFail) {
  EXPECT_CALL(mock_tpm_utility_, ReadPCR(5, _))
      .WillOnce(Return(TPM_RC_FAILURE));
  std::string value;
  EXPECT_FALSE(tpm_utility_->ReadPCR(5, &value));
  EXPECT_EQ("", value);
}

TEST_F(TpmUtilityTest, CertifyNVWithRsa) {
  constexpr int kFakeNvIndex = 0x123;
  constexpr int kFakeNvSize = 0x456;

  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_RSASSA;
  fake_signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_quote");

  std::string fake_quoted_data = GenerateFakeQuotedData(kNvRamData);

  EXPECT_CALL(mock_tpm_, NV_CertifySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<7>(trunks::Make_TPM2B_ATTEST(fake_quoted_data)),
                SetArgPointee<8>(fake_signature), Return(TPM_RC_SUCCESS)));

  std::string quoted_data;
  std::string quote;
  EXPECT_TRUE(tpm_utility_->CertifyNV(kFakeNvIndex, kFakeNvSize,
                                      "fake_key_blob", &quoted_data, &quote));
  EXPECT_EQ(quoted_data, fake_quoted_data);
  EXPECT_NE(quote.find("fake_quote"), std::string::npos);
}

TEST_F(TpmUtilityTest, CertifyNVWithEcc) {
  constexpr int kFakeNvIndex = 0x123;
  constexpr int kFakeNvSize = 0x456;

  EXPECT_CALL(mock_tpm_utility_, GetKeyPublicArea(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(GetValidEccPublicKey(nullptr)),
                      Return(TPM_RC_SUCCESS)));

  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_ECDSA;
  fake_signature.signature.ecdsa.signature_r =
      trunks::Make_TPM2B_ECC_PARAMETER("fake_quote_r");
  fake_signature.signature.ecdsa.signature_s =
      trunks::Make_TPM2B_ECC_PARAMETER("fake_quote_s");

  std::string fake_quoted_data = GenerateFakeQuotedData(kNvRamData);

  EXPECT_CALL(mock_tpm_, NV_CertifySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<7>(trunks::Make_TPM2B_ATTEST(fake_quoted_data)),
                SetArgPointee<8>(fake_signature), Return(TPM_RC_SUCCESS)));

  std::string quoted_data;
  std::string quote;
  EXPECT_TRUE(tpm_utility_->CertifyNV(kFakeNvIndex, kFakeNvSize,
                                      "fake_key_blob", &quoted_data, &quote));
  EXPECT_EQ(quoted_data, fake_quoted_data);
  EXPECT_NE(quote.find("fake_quote_r"), std::string::npos);
  EXPECT_NE(quote.find("fake_quote_s"), std::string::npos);
}

TEST_F(TpmUtilityTest, CertifyNVEmptyContent) {
  constexpr int kFakeNvIndex = 0x123;
  constexpr int kFakeNvSize = 0x456;

  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_RSASSA;
  fake_signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_quote");

  std::string fake_quoted_data = GenerateFakeQuotedData("");

  EXPECT_CALL(mock_tpm_, NV_CertifySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<7>(trunks::Make_TPM2B_ATTEST(fake_quoted_data)),
                SetArgPointee<8>(fake_signature), Return(TPM_RC_SUCCESS)));

  std::string quoted_data;
  std::string quote;
  EXPECT_FALSE(tpm_utility_->CertifyNV(kFakeNvIndex, kFakeNvSize,
                                       "fake_key_blob", &quoted_data, &quote));
  EXPECT_EQ(quoted_data, "");
  EXPECT_EQ(quote, "");
}

TEST_F(TpmUtilityTest, CertifyNVAll0Content) {
  constexpr int kFakeNvIndex = 0x123;
  constexpr int kFakeNvSize = 0x456;

  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_RSASSA;
  fake_signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_quote");

  std::string fake_quoted_data =
      GenerateFakeQuotedData(std::string(16, trunks::BYTE(0)));

  EXPECT_CALL(mock_tpm_, NV_CertifySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<7>(trunks::Make_TPM2B_ATTEST(fake_quoted_data)),
                SetArgPointee<8>(fake_signature), Return(TPM_RC_SUCCESS)));

  std::string quoted_data;
  std::string quote;
  EXPECT_FALSE(tpm_utility_->CertifyNV(kFakeNvIndex, kFakeNvSize,
                                       "fake_key_blob", &quoted_data, &quote));
  EXPECT_EQ(quoted_data, "");
  EXPECT_EQ(quote, "");
}

TEST_F(TpmUtilityTest, CertifyNVAll1Content) {
  constexpr int kFakeNvIndex = 0x123;
  constexpr int kFakeNvSize = 0x456;

  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_RSASSA;
  fake_signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_quote");

  std::string fake_quoted_data =
      GenerateFakeQuotedData(std::string(16, trunks::BYTE(255)));

  EXPECT_CALL(mock_tpm_, NV_CertifySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(
          DoAll(SetArgPointee<7>(trunks::Make_TPM2B_ATTEST(fake_quoted_data)),
                SetArgPointee<8>(fake_signature), Return(TPM_RC_SUCCESS)));

  std::string quoted_data;
  std::string quote;
  EXPECT_FALSE(tpm_utility_->CertifyNV(kFakeNvIndex, kFakeNvSize,
                                       "fake_key_blob", &quoted_data, &quote));
  EXPECT_EQ(quoted_data, "");
  EXPECT_EQ(quote, "");
}

TEST_F(TpmUtilityTest, CertifyNVFail) {
  constexpr int kFakeNvIndex = 0x123;
  constexpr int kFakeNvSize = 0x456;

  trunks::TPMT_SIGNATURE fake_signature;
  fake_signature.sig_alg = trunks::TPM_ALG_RSASSA;
  fake_signature.signature.rsassa.sig =
      trunks::Make_TPM2B_PUBLIC_KEY_RSA("fake_quote");
  EXPECT_CALL(mock_tpm_, NV_CertifySyncShort(_, _, _, _, _, _, _, _, _, _))
      .WillOnce(Return(TPM_RC_FAILURE));

  std::string quoted_data;
  std::string quote;
  EXPECT_FALSE(tpm_utility_->CertifyNV(kFakeNvIndex, kFakeNvSize,
                                       "fake_key_blob", &quoted_data, &quote));
  EXPECT_EQ(quoted_data, "");
  EXPECT_EQ(quote, "");
}

}  // namespace attestation
