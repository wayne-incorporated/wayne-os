// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/u2f_command_processor_generic.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/u2fd/mock_frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <user_data_auth-client-test/user_data_auth/dbus-proxy-mocks.h>
#include <user_data_auth-client/user_data_auth/dbus-proxies.h>

#include "u2fd/client/util.h"
#include "u2fd/mock_user_state.h"
#include "u2fd/u2f_command_processor.h"

namespace u2f {

namespace {

using hwsec::TPMError;
using hwsec::TPMRetryAction;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;

using ::testing::_;
using ::testing::DoAll;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

using CreateKeyResult = hwsec::U2fFrontend::CreateKeyResult;

constexpr char kCredentialSecretHex[65] = {[0 ... 63] = 'F', '\0'};
constexpr char kUserAccount[5] = "user";
constexpr char kWebAuthnSecretString[33] = {[0 ... 31] = '\x12', '\0'};
// Dummy RP id.
constexpr char kRpId[] = "example.com";
// Wrong RP id is used to test app id extension path.
constexpr char kWrongRpId[] = "wrong.com";

brillo::Blob HexArrayToBlob(const char* array) {
  brillo::Blob blob;
  CHECK(base::HexStringToBytes(array, &blob));
  return blob;
}

std::string ToString(const std::vector<uint8_t>& v) {
  return std::string(v.begin(), v.end());
}

brillo::SecureBlob GetWebAuthnSecret() {
  return brillo::SecureBlob(kWebAuthnSecretString);
}

brillo::SecureBlob GetCredentialSecret() {
  return brillo::SecureBlob(HexArrayToBlob(kCredentialSecretHex));
}

std::vector<uint8_t> GetRpIdHash() {
  return util::Sha256(std::string(kRpId));
}

std::vector<uint8_t> GetWrongRpIdHash() {
  return util::Sha256(std::string(kWrongRpId));
}

std::vector<uint8_t> GetKeyBlob() {
  return std::vector<uint8_t>(256, '\x13');
}

std::vector<uint8_t> GetFakeKeyBlob() {
  return std::vector<uint8_t>(256, '\x14');
}

std::vector<uint8_t> GetFakeCredentialIdWithoutHash() {
  return util::ToVector(std::string(1, '\x01') + std::string(3, '\x00') +
                        std::string(48, 'C'));
}
std::vector<uint8_t> GetFakeCredentialIdHash() {
  return util::Sha256(GetFakeCredentialIdWithoutHash());
}
std::vector<uint8_t> GetFakeCredentialIdValidHash() {
  return util::ToVector(ToString(GetFakeCredentialIdWithoutHash()) +
                        ToString(GetFakeCredentialIdHash()));
}
std::vector<uint8_t> GetFakeCredentialIdInvalidHash() {
  return util::ToVector(ToString(GetFakeCredentialIdWithoutHash()) +
                        std::string(32, 'S'));
}

std::vector<uint8_t> GetPubExponent() {
  return std::vector<uint8_t>{'\x01', '\x00', '\x01'};
}

std::vector<uint8_t> GetModulus() {
  return std::vector<uint8_t>(256, 'M');
}

std::vector<uint8_t> GetHashToSign() {
  return std::vector<uint8_t>(32, 'H');
}

std::vector<uint8_t> GetSignature() {
  return std::vector<uint8_t>(128, 'S');
}

}  // namespace

class U2fCommandProcessorGenericTest : public ::testing::Test {
 public:
  void SetUp() override {
    auto mock_u2f_frontend = std::make_unique<hwsec::MockU2fFrontend>();
    mock_u2f_frontend_ = mock_u2f_frontend.get();
    auto mock_cryptohome_proxy =
        std::make_unique<org::chromium::UserDataAuthInterfaceProxyMock>();
    mock_cryptohome_proxy_ = mock_cryptohome_proxy.get();
    processor_ = std::make_unique<U2fCommandProcessorGeneric>(
        &mock_user_state_, std::move(mock_cryptohome_proxy),
        std::move(mock_u2f_frontend));
    ExpectNoGetWebAuthnSecret();
    ExpectGetUser();
  }

 protected:
  void ExpectNoGetWebAuthnSecret() {
    EXPECT_CALL(*mock_cryptohome_proxy_, GetWebAuthnSecret(_, _, _, _))
        .Times(0);
  }

  void ExpectGetWebAuthnSecret() {
    user_data_auth::GetWebAuthnSecretReply reply;
    reply.set_webauthn_secret(kWebAuthnSecretString);
    EXPECT_CALL(*mock_cryptohome_proxy_, GetWebAuthnSecret(_, _, _, _))
        .WillOnce(DoAll(SetArgPointee<1>(reply), Return(true)));
  }

  void ExpectGetWebAuthnSecretFail() {
    EXPECT_CALL(*mock_cryptohome_proxy_, GetWebAuthnSecret(_, _, _, _))
        .WillOnce(Return(false));
  }

  void ExpectGetUser() {
    EXPECT_CALL(mock_user_state_, GetUser())
        .WillRepeatedly(Return(kUserAccount));
  }

  void ExpectFrontendReady() {
    EXPECT_CALL(*mock_u2f_frontend_, IsReady())
        .WillRepeatedly(ReturnValue(true));
  }

  MakeCredentialResponse::MakeCredentialStatus U2fGenerate(
      std::vector<uint8_t>* credential_id,
      CredentialPublicKey* credential_pubkey,
      std::vector<uint8_t>* credential_key_blob) {
    return processor_->U2fGenerate(
        GetRpIdHash(), GetCredentialSecret(), PresenceRequirement::kNone,
        /*uv_compatible=*/true, /*auth_time_secret_hash=*/nullptr,
        credential_id, credential_pubkey, credential_key_blob);
  }

  GetAssertionResponse::GetAssertionStatus U2fSign(
      const std::vector<uint8_t>& rp_id_hash,
      const std::vector<uint8_t>& hash_to_sign,
      const std::vector<uint8_t>& credential_id,
      const std::vector<uint8_t>* credential_key_blob,
      std::vector<uint8_t>* signature) {
    return processor_->U2fSign(rp_id_hash, hash_to_sign, credential_id,
                               GetCredentialSecret(), credential_key_blob,
                               PresenceRequirement::kNone, signature);
  }

  HasCredentialsResponse::HasCredentialsStatus U2fSignCheckOnly(
      const std::vector<uint8_t>& rp_id_hash,
      const std::vector<uint8_t>& credential_id,
      const std::vector<uint8_t>* credential_key_blob) {
    return processor_->U2fSignCheckOnly(
        rp_id_hash, credential_id, GetCredentialSecret(), credential_key_blob);
  }

  hwsec::ScopedKey GetTestScopedKey() {
    return hwsec::ScopedKey(hwsec::Key{.token = 42},
                            mock_u2f_frontend_->GetFakeMiddlewareDerivative());
  }

  StrictMock<MockUserState> mock_user_state_;
  org::chromium::UserDataAuthInterfaceProxyMock* mock_cryptohome_proxy_;
  hwsec::MockU2fFrontend* mock_u2f_frontend_;

 private:
  std::unique_ptr<U2fCommandProcessorGeneric> processor_;
};

namespace {

TEST_F(U2fCommandProcessorGenericTest, U2fGenerateNoWebAuthnSecret) {
  std::vector<uint8_t> cred_id, cred_key_blob;
  CredentialPublicKey cred_pubkey;
  ExpectGetWebAuthnSecretFail();
  EXPECT_EQ(U2fGenerate(&cred_id, &cred_pubkey, &cred_key_blob),
            MakeCredentialResponse::INTERNAL_ERROR);
}

TEST_F(U2fCommandProcessorGenericTest, U2fGenerateFrontendNotReady) {
  std::vector<uint8_t> cred_id, cred_key_blob;
  CredentialPublicKey cred_pubkey;
  ExpectGetWebAuthnSecret();
  EXPECT_CALL(*mock_u2f_frontend_, IsReady()).WillOnce(ReturnValue(false));
  EXPECT_EQ(U2fGenerate(&cred_id, &cred_pubkey, &cred_key_blob),
            MakeCredentialResponse::INTERNAL_ERROR);
}

TEST_F(U2fCommandProcessorGenericTest, U2fGenerateFrontendCreateKeyFailed) {
  std::vector<uint8_t> cred_id, cred_key_blob;
  CredentialPublicKey cred_pubkey;
  ExpectGetWebAuthnSecret();
  ExpectFrontendReady();
  EXPECT_CALL(*mock_u2f_frontend_, GenerateRSASigningKey(GetWebAuthnSecret()))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  EXPECT_EQ(U2fGenerate(&cred_id, &cred_pubkey, &cred_key_blob),
            MakeCredentialResponse::INTERNAL_ERROR);
}

TEST_F(U2fCommandProcessorGenericTest, U2fSignNoCredentialKeyBlob) {
  std::vector<uint8_t> signature;
  EXPECT_EQ(
      U2fSign(GetRpIdHash(), GetHashToSign(), GetFakeCredentialIdValidHash(),
              /*credential_key_blob=*/nullptr, &signature),
      GetAssertionResponse::INVALID_REQUEST);
}

TEST_F(U2fCommandProcessorGenericTest, U2fSignInvalidHash) {
  std::vector<uint8_t> signature;
  auto fake_key_blob = GetFakeKeyBlob();
  EXPECT_EQ(
      U2fSign(GetRpIdHash(), GetHashToSign(), GetFakeCredentialIdInvalidHash(),
              &fake_key_blob, &signature),
      GetAssertionResponse::INVALID_REQUEST);
}

TEST_F(U2fCommandProcessorGenericTest, U2fSignInvalidHmac) {
  std::vector<uint8_t> signature;
  ExpectGetWebAuthnSecret();
  auto fake_key_blob = GetFakeKeyBlob();
  EXPECT_EQ(U2fSign(GetRpIdHash(), GetHashToSign(),
                    GetFakeCredentialIdValidHash(), &fake_key_blob, &signature),
            GetAssertionResponse::INTERNAL_ERROR);
}

TEST_F(U2fCommandProcessorGenericTest, U2fSignWrongRpIdHash) {
  std::vector<uint8_t> cred_id, cred_key_blob;
  CredentialPublicKey cred_pubkey;
  ExpectGetWebAuthnSecret();
  ExpectFrontendReady();
  EXPECT_CALL(*mock_u2f_frontend_, GenerateRSASigningKey(GetWebAuthnSecret()))
      .WillOnce([&](auto&&) {
        return CreateKeyResult{
            .key = GetTestScopedKey(),
            .key_blob = GetKeyBlob(),
        };
      });
  EXPECT_CALL(*mock_u2f_frontend_, GetRSAPublicKey)
      .WillOnce(ReturnValue(hwsec::RSAPublicInfo{
          .exponent = GetPubExponent(),
          .modulus = GetModulus(),
      }));
  EXPECT_EQ(U2fGenerate(&cred_id, &cred_pubkey, &cred_key_blob),
            MakeCredentialResponse::SUCCESS);
  EXPECT_FALSE(cred_pubkey.cbor.empty());

  // U2fSign with wrong rp id hash should fail.
  std::vector<uint8_t> signature;
  ExpectGetWebAuthnSecret();
  EXPECT_EQ(U2fSign(GetWrongRpIdHash(), GetHashToSign(), cred_id,
                    &cred_key_blob, &signature),
            GetAssertionResponse::INTERNAL_ERROR);
}

TEST_F(U2fCommandProcessorGenericTest, U2fSignCheckOnlyTooLongCredId) {
  std::vector<uint8_t> cred_id(GetFakeCredentialIdValidHash());
  cred_id.push_back('C');
  auto fake_key_blob = GetFakeKeyBlob();
  EXPECT_EQ(U2fSignCheckOnly(GetRpIdHash(), cred_id, &fake_key_blob),
            HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID);
}

TEST_F(U2fCommandProcessorGenericTest, U2fSignCheckOnlyInvalidHash) {
  auto fake_key_blob = GetFakeKeyBlob();
  EXPECT_EQ(U2fSignCheckOnly(GetRpIdHash(), GetFakeCredentialIdInvalidHash(),
                             &fake_key_blob),
            HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID);
}

TEST_F(U2fCommandProcessorGenericTest, U2fGenerateSignSuccess) {
  std::vector<uint8_t> cred_id, cred_key_blob;
  CredentialPublicKey cred_pubkey;
  ExpectGetWebAuthnSecret();
  ExpectFrontendReady();
  EXPECT_CALL(*mock_u2f_frontend_, GenerateRSASigningKey(GetWebAuthnSecret()))
      .WillOnce([&](auto&&) {
        return CreateKeyResult{
            .key = GetTestScopedKey(),
            .key_blob = GetKeyBlob(),
        };
      });
  EXPECT_CALL(*mock_u2f_frontend_, GetRSAPublicKey)
      .WillOnce(ReturnValue(hwsec::RSAPublicInfo{
          .exponent = GetPubExponent(),
          .modulus = GetModulus(),
      }));
  EXPECT_EQ(U2fGenerate(&cred_id, &cred_pubkey, &cred_key_blob),
            MakeCredentialResponse::SUCCESS);
  EXPECT_FALSE(cred_pubkey.cbor.empty());

  // U2fSignCheckOnly should succeed.
  EXPECT_EQ(U2fSignCheckOnly(GetRpIdHash(), cred_id, &cred_key_blob),
            HasCredentialsResponse::SUCCESS);

  // U2fSign should succeed.
  std::vector<uint8_t> signature;
  ExpectGetWebAuthnSecret();
  EXPECT_CALL(*mock_u2f_frontend_, LoadKey(GetKeyBlob(), GetWebAuthnSecret()))
      .WillOnce([&](auto&&, auto&&) { return GetTestScopedKey(); });
  EXPECT_CALL(*mock_u2f_frontend_, RSASign(_, GetHashToSign()))
      .WillOnce(ReturnValue(GetSignature()));
  EXPECT_EQ(U2fSign(GetRpIdHash(), GetHashToSign(), cred_id, &cred_key_blob,
                    &signature),
            GetAssertionResponse::SUCCESS);
  EXPECT_EQ(signature, GetSignature());
}

}  // namespace

}  // namespace u2f
