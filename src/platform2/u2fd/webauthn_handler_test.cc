// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/webauthn_handler.h"

#include <optional>
#include <regex>  // NOLINT(build/c++11)
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <chromeos/cbor/values.h>
#include <chromeos/cbor/writer.h>
#include <chromeos/dbus/service_constants.h>
#include <dbus/bus.h>
#include <dbus/mock_bus.h>
#include <dbus/mock_object_proxy.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <metrics/metrics_library_mock.h>
#include <user_data_auth-client-test/user_data_auth/dbus-proxy-mocks.h>

#include "u2fd/client/util.h"
#include "u2fd/mock_allowlisting_util.h"
#include "u2fd/mock_u2f_command_processor.h"
#include "u2fd/mock_user_state.h"
#include "u2fd/mock_webauthn_storage.h"

namespace u2f {
namespace {

using ::brillo::dbus_utils::MockDBusMethodResponse;

using ::testing::_;
using ::testing::DoAll;
using ::testing::Matcher;
using ::testing::MatchesRegex;
using ::testing::Pointee;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;
using ::testing::Unused;

// Dummy User State.
constexpr char kUserSecret[65] = {[0 ... 63] = 'E', '\0'};
constexpr char kCredentialSecret[65] = {[0 ... 63] = 'F', '\0'};
// Dummy RP id.
constexpr char kRpId[] = "example.com";
// Wrong RP id is used to test app id extension path.
constexpr char kWrongRpId[] = "wrong.com";

// AuthenticatorData field sizes, in bytes.
constexpr int kRpIdHashBytes = 32;
constexpr int kAuthenticatorDataFlagBytes = 1;
constexpr int kSignatureCounterBytes = 4;
constexpr int kAaguidBytes = 16;
constexpr int kCredentialIdLengthBytes = 2;

std::vector<uint8_t> GetAuthTimeSecretHash() {
  return std::vector<uint8_t>(32, 0x12);
}

std::vector<uint8_t> GetRpIdHash() {
  return util::Sha256(std::string(kRpId));
}

std::vector<uint8_t> GetWrongRpIdHash() {
  return util::Sha256(std::string(kWrongRpId));
}

brillo::SecureBlob GetCorrectUserSecret() {
  return brillo::SecureBlob(32, '\xee');
}

std::string GetClientDataHash() {
  return std::string(SHA256_DIGEST_LENGTH, 0xcd);
}

// // AAGUID for none attestation.
std::vector<uint8_t> GetAaguid() {
  return std::vector<uint8_t>{0x84, 0x03, 0x98, 0x77, 0xa5, 0x4b, 0xdf, 0xbb,
                              0x04, 0xa8, 0x2d, 0xf2, 0xfa, 0x2a, 0x11, 0x6e};
}

std::vector<uint8_t> GetCredId() {
  return std::vector<uint8_t>(64, 0xFD);
}

std::vector<uint8_t> GetVersionedCredId() {
  return std::vector<uint8_t>(145, 0xFD);
}

std::string GetCredIdString() {
  auto cred_id = GetCredId();
  return std::string(cred_id.begin(), cred_id.end());
}

std::string GetVersionedCredIdString() {
  auto cred_id = GetVersionedCredId();
  return std::string(cred_id.begin(), cred_id.end());
}

CredentialPublicKey GetCredPubKey() {
  return CredentialPublicKey{
      .cbor = std::vector<uint8_t>(65, 0xAB),
      .raw = std::vector<uint8_t>(65, 0xAB),
  };
}

std::vector<uint8_t> GetSignature() {
  return *util::SignatureToDerBytes(std::vector<uint8_t>(32, 0x12),
                                    std::vector<uint8_t>(32, 0x34));
}

brillo::SecureBlob ArrayToSecureBlob(const char* array) {
  brillo::SecureBlob blob;
  CHECK(brillo::SecureBlob::HexStringToSecureBlob(array, &blob));
  return blob;
}

// Example of a cert that would be returned by cr50.
constexpr char kDummyG2fCert[] =
    "308201363081DDA0030201020210442D32429223D041240350303716EE6B300A06082A8648"
    "CE3D040302300F310D300B06035504031304637235303022180F3230303030313031303030"
    "3030305A180F32303939313233313233353935395A300F310D300B06035504031304637235"
    "303059301306072A8648CE3D020106082A8648CE3D030107034200045165719A9975F6FD30"
    "CC2516C22FE841F65F9D2EE7B8B72F76807AEBD8CA3376005C7FA86453E4B10DB7BFAD5D2B"
    "D00DB4A7C4845AD06D686ACD0252387618ECA31730153013060B2B0601040182E51C020101"
    "040403020308300A06082A8648CE3D0403020348003045022100F09976F373920FEF8205C4"
    "B1FB1DA21EB9F3F176B7DF433A1ADE0F3F38B721960220179D9B9051BFCCCC90BA6BB42B86"
    "111D7A9C4FB56DFD39FB426081DD027AD609";

std::vector<uint8_t> GetDummyG2fCert() {
  std::vector<uint8_t> cert;
  base::HexStringToBytes(kDummyG2fCert, &cert);
  return cert;
}

}  // namespace

// TODO(b/205813697): Add tests for generic TPM flow.
// The base test fixture tests behaviors seen by general consumers. It
// disallows presence-only mode, because U2F isn't offered to general
// consumers.
class WebAuthnHandlerTestBase : public ::testing::Test {
 public:
  void SetUp() override {
    PrepareMockBus();
    CreateHandler(U2fMode::kDisabled, /*allowlisting_util=*/nullptr);
    PrepareMockStorage();
    // We use per-credential secret instead of the old user secret.
    ExpectNoGetUserSecret();
  }

 protected:
  void PrepareMockBus() {
    dbus::Bus::Options options;
    options.bus_type = dbus::Bus::SYSTEM;
    mock_bus_ = new dbus::MockBus(options);

    mock_auth_dialog_proxy_ = new dbus::MockObjectProxy(
        mock_bus_.get(), chromeos::kUserAuthenticationServiceName,
        dbus::ObjectPath(chromeos::kUserAuthenticationServicePath));

    // Set an expectation so that the MockBus will return our mock proxy.
    EXPECT_CALL(*mock_bus_,
                GetObjectProxy(
                    chromeos::kUserAuthenticationServiceName,
                    dbus::ObjectPath(chromeos::kUserAuthenticationServicePath)))
        .WillOnce(Return(mock_auth_dialog_proxy_.get()));
  }

  void CreateHandler(U2fMode u2f_mode,
                     std::unique_ptr<AllowlistingUtil> allowlisting_util) {
    handler_ = std::make_unique<WebAuthnHandler>();
    PrepareMockCryptohome();
    auto mock_processor = std::make_unique<MockU2fCommandProcessor>();
    mock_processor_ = mock_processor.get();
    handler_->Initialize(mock_bus_.get(), &mock_user_state_, u2f_mode,
                         std::move(mock_processor),
                         std::move(allowlisting_util), &mock_metrics_);
  }

  void PrepareMockCryptohome() {
    auto mock_cryptohome_proxy =
        std::make_unique<org::chromium::UserDataAuthInterfaceProxyMock>();
    mock_cryptohome_proxy_ = mock_cryptohome_proxy.get();
    handler_->SetCryptohomeInterfaceProxyForTesting(
        std::move(mock_cryptohome_proxy));
  }

  void PrepareMockStorage() {
    auto mock_storage = std::make_unique<MockWebAuthnStorage>();
    mock_webauthn_storage_ = mock_storage.get();
    handler_->SetWebAuthnStorageForTesting(std::move(mock_storage));
    mock_webauthn_storage_->set_allow_access(true);
  }

  void ExpectUVFlowSuccess() {
    mock_auth_dialog_response_ = dbus::Response::CreateEmpty();
    dbus::Response* response = mock_auth_dialog_response_.get();
    dbus::MessageWriter writer(response);
    writer.AppendBool(true);
    EXPECT_CALL(*mock_auth_dialog_proxy_, DoCallMethod(_, _, _))
        .WillOnce(
            [response](Unused, Unused,
                       base::OnceCallback<void(dbus::Response*)>* callback) {
              std::move(*callback).Run(response);
            });
  }

  void ExpectNoGetUserSecret() {
    EXPECT_CALL(mock_user_state_, GetUserSecret()).Times(0);
  }

  void ExpectGetUserSecret() { ExpectGetUserSecretForTimes(1); }

  void ExpectGetUserSecretForTimes(int times) {
    EXPECT_CALL(mock_user_state_, GetUserSecret())
        .Times(times)
        .WillRepeatedly(Return(ArrayToSecureBlob(kUserSecret)));
  }

  void ExpectGetCounter() {
    static const std::vector<uint8_t> kSignatureCounter({42, 23, 42, 23});
    EXPECT_CALL(mock_user_state_, GetCounter())
        .WillOnce(Return(kSignatureCounter));
  }

  void ExpectIncrementCounter() {
    EXPECT_CALL(mock_user_state_, IncrementCounter()).WillOnce(Return(true));
  }

  std::vector<uint8_t> MakeAuthenticatorData(
      const std::vector<uint8_t>& credential_id,
      const std::vector<uint8_t>& credential_public_key,
      bool user_verified,
      bool include_attested_credential_data,
      bool is_u2f_authenticator_credential) {
    std::optional<std::vector<uint8_t>> authenticator_data =
        handler_->MakeAuthenticatorData(
            GetRpIdHash(), credential_id, credential_public_key, user_verified,
            include_attested_credential_data, is_u2f_authenticator_credential);
    DCHECK(authenticator_data);
    return *authenticator_data;
  }

  // Set up an auth-time secret hash as if a user has logged in.
  void SetUpAuthTimeSecretHash() {
    handler_->auth_time_secret_hash_ =
        std::make_unique<brillo::Blob>(GetAuthTimeSecretHash());
  }

  StrictMock<MockUserState> mock_user_state_;

  std::unique_ptr<WebAuthnHandler> handler_;
  MockWebAuthnStorage* mock_webauthn_storage_;
  MockU2fCommandProcessor* mock_processor_;

 private:
  scoped_refptr<dbus::MockBus> mock_bus_;
  scoped_refptr<dbus::MockObjectProxy> mock_auth_dialog_proxy_;
  std::unique_ptr<dbus::Response> mock_auth_dialog_response_;
  org::chromium::UserDataAuthInterfaceProxyMock* mock_cryptohome_proxy_;
  testing::NiceMock<MetricsLibraryMock> mock_metrics_;
};

namespace {

TEST_F(WebAuthnHandlerTestBase, MakeCredentialUninitialized) {
  // Use an uninitialized WebAuthnHandler object.
  handler_.reset(new WebAuthnHandler());
  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<MakeCredentialResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const MakeCredentialResponse& resp) {
        EXPECT_EQ(resp.status(), MakeCredentialResponse::INTERNAL_ERROR);
        *called_ptr = true;
      },
      &called));

  MakeCredentialRequest request;
  handler_->MakeCredential(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestBase, MakeCredentialEmptyRpId) {
  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<MakeCredentialResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const MakeCredentialResponse& resp) {
        EXPECT_EQ(resp.status(), MakeCredentialResponse::INVALID_REQUEST);
        *called_ptr = true;
      },
      &called));

  MakeCredentialRequest request;
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);
  handler_->MakeCredential(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestBase, MakeCredentialNoAuthTimeSecretHash) {
  MakeCredentialRequest request;
  request.set_rp_id(kRpId);
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);

  ExpectUVFlowSuccess();
  EXPECT_CALL(*mock_processor_,
              U2fGenerate(GetRpIdHash(), _, PresenceRequirement::kNone, true,
                          nullptr, _, _, _))
      .WillRepeatedly(Return(MakeCredentialResponse::INTERNAL_ERROR));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<MakeCredentialResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const MakeCredentialResponse& resp) {
        EXPECT_EQ(resp.status(), MakeCredentialResponse::INTERNAL_ERROR);
        *called_ptr = true;
      },
      &called));

  handler_->MakeCredential(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestBase, MakeCredentialUPUpgradedToUV) {
  MakeCredentialRequest request;
  request.set_rp_id(kRpId);
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);

  // Though it's going to be UV, we will still check if any exclude credential
  // matches legacy credentials.
  ExpectGetUserSecret();
  ExpectUVFlowSuccess();
  SetUpAuthTimeSecretHash();
  EXPECT_CALL(*mock_processor_,
              U2fGenerate(GetRpIdHash(), _, PresenceRequirement::kNone, true,
                          Pointee(GetAuthTimeSecretHash()), _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(GetVersionedCredId()),
                      SetArgPointee<6>(GetCredPubKey()),
                      Return(MakeCredentialResponse::SUCCESS)));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<MakeCredentialResponse>>();
  handler_->MakeCredential(std::move(mock_method_response), request);
}

TEST_F(WebAuthnHandlerTestBase, MakeCredentialVerificationSuccess) {
  MakeCredentialRequest request;
  request.set_rp_id(kRpId);
  request.set_verification_type(
      VerificationType::VERIFICATION_USER_VERIFICATION);

  // Thought it's going to be UV, we will still check if any exclude credential
  // matches legacy credentials.
  ExpectGetUserSecret();
  ExpectUVFlowSuccess();

  SetUpAuthTimeSecretHash();
  EXPECT_CALL(*mock_processor_,
              U2fGenerate(GetRpIdHash(), _, PresenceRequirement::kNone, true,
                          Pointee(GetAuthTimeSecretHash()), _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(GetVersionedCredId()),
                      SetArgPointee<6>(GetCredPubKey()),
                      Return(MakeCredentialResponse::SUCCESS)));
  // TODO(yichengli): Specify the parameter to WriteRecord.
  EXPECT_CALL(*mock_webauthn_storage_, WriteRecord(_)).WillOnce(Return(true));

  auto rp_id_hash = GetRpIdHash();
  auto aaguid = GetAaguid();

  const std::string expected_authenticator_data_regex =
      base::HexEncode(rp_id_hash.data(),
                      rp_id_hash.size()) +  // RP ID hash
      std::string(
          "45"          // Flag: user present, user verified, attested
                        // credential data included.
          "(..){4}") +  // Signature counter
      base::HexEncode(aaguid.data(), aaguid.size()) +  // AAGUID
      std::string(
          "0091"      // Credential ID length
                      // Credential ID, from kU2fGenerateVersionedResponse:
          "(FD){65}"  // Versioned key handle header
          "(FD){16}"  // Authorization salt
          "(FD){32}"  // Hash of authorization secret
          "(FD){32}"  // Authorization hmac
                      // CBOR encoded credential public key:
          "(AB){65}");

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<MakeCredentialResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const std::string& expected_authenticator_data,
         const MakeCredentialResponse& resp) {
        EXPECT_EQ(resp.status(), MakeCredentialResponse::SUCCESS);
        EXPECT_THAT(base::HexEncode(resp.authenticator_data().data(),
                                    resp.authenticator_data().size()),
                    MatchesRegex(expected_authenticator_data));
        EXPECT_EQ(resp.attestation_format(), "none");
        EXPECT_EQ(resp.attestation_statement(), "\xa0");
        *called_ptr = true;
      },
      &called, expected_authenticator_data_regex));

  handler_->MakeCredential(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestBase, GetAssertionUninitialized) {
  // Use an uninitialized WebAuthnHandler object.
  handler_.reset(new WebAuthnHandler());
  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const GetAssertionResponse& resp) {
        EXPECT_EQ(resp.status(), GetAssertionResponse::INTERNAL_ERROR);
        *called_ptr = true;
      },
      &called));

  GetAssertionRequest request;
  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestBase, GetAssertionEmptyRpId) {
  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const GetAssertionResponse& resp) {
        EXPECT_EQ(resp.status(), GetAssertionResponse::INVALID_REQUEST);
        *called_ptr = true;
      },
      &called));

  GetAssertionRequest request;
  request.set_client_data_hash(GetClientDataHash());
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);
  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestBase, GetAssertionWrongClientDataHashLength) {
  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const GetAssertionResponse& resp) {
        EXPECT_EQ(resp.status(), GetAssertionResponse::INVALID_REQUEST);
        *called_ptr = true;
      },
      &called));

  GetAssertionRequest request;
  request.set_rp_id(kRpId);
  request.set_client_data_hash(std::string(SHA256_DIGEST_LENGTH - 1, 0xcd));
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);
  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

// Simulates the case where the KH doesn't match any record in daemon-store, or
// any legacy credential id.
TEST_F(WebAuthnHandlerTestBase, GetAssertionNoCredentialSecret) {
  GetAssertionRequest request;
  request.set_rp_id(kWrongRpId);
  request.set_app_id(kWrongRpId);
  request.set_client_data_hash(GetClientDataHash());
  request.add_allowed_credential_id(GetCredIdString());
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);

  EXPECT_CALL(*mock_webauthn_storage_,
              GetSecretAndKeyBlobByCredentialId(GetCredIdString(), _, _))
      .WillOnce(Return(false));
  ExpectGetUserSecret();

  // We will check for legacy credentials, so two check-only calls to TPM.
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetWrongRpIdHash(), GetCredId(),
                               GetCorrectUserSecret(), _))
      .Times(2)
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const GetAssertionResponse& resp) {
        EXPECT_EQ(resp.status(), GetAssertionResponse::UNKNOWN_CREDENTIAL_ID);
        *called_ptr = true;
      },
      &called));

  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

// Simulates the case where the KH matches a record in daemon-store but is not
// recognized by cr50. This is not very likely in reality unless daemon-store is
// compromised.
TEST_F(WebAuthnHandlerTestBase, GetAssertionInvalidKeyHandle) {
  GetAssertionRequest request;
  request.set_rp_id(kWrongRpId);
  request.set_app_id(kWrongRpId);
  request.set_client_data_hash(GetClientDataHash());
  request.add_allowed_credential_id(GetCredIdString());
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);

  EXPECT_CALL(*mock_webauthn_storage_,
              GetSecretAndKeyBlobByCredentialId(GetCredIdString(), _, _))
      .WillOnce(DoAll(SetArgPointee<1>(ArrayToSecureBlob(kCredentialSecret)),
                      Return(true)));
  ExpectGetUserSecret();
  // 3 calls to SignCheckOnly, one for each credential type.
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetWrongRpIdHash(), GetCredId(), _, _))
      .Times(3)
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const GetAssertionResponse& resp) {
        EXPECT_EQ(resp.status(), GetAssertionResponse::UNKNOWN_CREDENTIAL_ID);
        *called_ptr = true;
      },
      &called));

  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestBase, GetAssertionUPUpgradedToUV) {
  // Needed for "InsertAuthTimeSecretHash" workaround.
  SetUpAuthTimeSecretHash();

  GetAssertionRequest request;
  request.set_rp_id(kRpId);
  request.set_client_data_hash(GetClientDataHash());
  request.add_allowed_credential_id(GetVersionedCredIdString());

  request.set_verification_type(
      VerificationType::VERIFICATION_USER_VERIFICATION);

  // Pass DoU2fSignCheckOnly so that we can get to UV flow.
  EXPECT_CALL(*mock_webauthn_storage_, GetSecretAndKeyBlobByCredentialId(
                                           GetVersionedCredIdString(), _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(ArrayToSecureBlob(kCredentialSecret)),
                Return(true)));
  ExpectGetUserSecret();

  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), GetVersionedCredId(),
                               ArrayToSecureBlob(kCredentialSecret), _))
      .WillRepeatedly(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(_, GetVersionedCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));
  EXPECT_CALL(*mock_processor_,
              U2fSign(GetRpIdHash(), _, GetVersionedCredId(),
                      ArrayToSecureBlob(kCredentialSecret), _,
                      PresenceRequirement::kAuthorizationSecret, _))
      .WillOnce(Return(GetAssertionResponse::SUCCESS));

  ExpectUVFlowSuccess();

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  handler_->GetAssertion(std::move(mock_method_response), request);
}

TEST_F(WebAuthnHandlerTestBase, GetAssertionVerificationSuccess) {
  // Needed for "InsertAuthTimeSecretHash" workaround.
  SetUpAuthTimeSecretHash();

  GetAssertionRequest request;
  request.set_rp_id(kRpId);
  request.set_client_data_hash(GetClientDataHash());

  request.add_allowed_credential_id(GetVersionedCredIdString());

  request.set_verification_type(
      VerificationType::VERIFICATION_USER_VERIFICATION);

  ExpectUVFlowSuccess();

  EXPECT_CALL(*mock_webauthn_storage_, GetSecretAndKeyBlobByCredentialId(
                                           GetVersionedCredIdString(), _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(ArrayToSecureBlob(kCredentialSecret)),
                Return(true)));

  ExpectGetUserSecret();

  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), GetVersionedCredId(),
                               ArrayToSecureBlob(kCredentialSecret), _))
      .WillRepeatedly(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(_, GetVersionedCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));
  EXPECT_CALL(*mock_processor_,
              U2fSign(GetRpIdHash(), _, GetVersionedCredId(),
                      ArrayToSecureBlob(kCredentialSecret), _,
                      PresenceRequirement::kAuthorizationSecret, _))
      .WillOnce(DoAll(SetArgPointee<6>(GetSignature()),
                      Return(GetAssertionResponse::SUCCESS)));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const std::string& expected_credential_id,
         const GetAssertionResponse& resp) {
        auto rp_id_hash = GetRpIdHash();
        EXPECT_EQ(resp.status(), GetAssertionResponse::SUCCESS);
        ASSERT_EQ(resp.assertion_size(), 1);
        auto assertion = resp.assertion(0);
        EXPECT_EQ(assertion.credential_id(), expected_credential_id);
        EXPECT_THAT(
            base::HexEncode(assertion.authenticator_data().data(),
                            assertion.authenticator_data().size()),
            MatchesRegex(base::HexEncode(rp_id_hash.data(),
                                         rp_id_hash.size()) +  // RP ID hash
                         std::string("05"  // Flag: user present, user verified
                                     "(..){4}")));  // Signature counter
        EXPECT_EQ(util::ToVector(assertion.signature()), GetSignature());
        *called_ptr = true;
      },
      &called, GetVersionedCredIdString()));

  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestBase, HasCredentialsNoMatch) {
  HasCredentialsRequest request;
  request.set_rp_id(kWrongRpId);
  request.set_app_id(kWrongRpId);
  request.add_credential_id(GetCredIdString());
  EXPECT_CALL(*mock_webauthn_storage_,
              GetSecretAndKeyBlobByCredentialId(GetCredIdString(), _, _))
      .WillRepeatedly(Return(false));
  ExpectGetUserSecret();

  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetWrongRpIdHash(), GetCredId(),
                               GetCorrectUserSecret(), _))
      .Times(2)
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));

  auto resp = handler_->HasCredentials(request);
  EXPECT_EQ(resp.credential_id_size(), 0);
  EXPECT_EQ(resp.status(), HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID);
}

// Match first of the 3 types of credentials, i.e. a credential generated by the
// platform authenticator with a versioned key handle.
TEST_F(WebAuthnHandlerTestBase, HasCredentialsMatchPlatformAuthenticator) {
  HasCredentialsRequest request;
  request.set_rp_id(kRpId);
  request.set_app_id(kRpId);
  request.add_credential_id(GetVersionedCredIdString());

  EXPECT_CALL(*mock_webauthn_storage_, GetSecretAndKeyBlobByCredentialId(
                                           GetVersionedCredIdString(), _, _))
      .WillOnce(DoAll(SetArgPointee<1>(ArrayToSecureBlob(kCredentialSecret)),
                      Return(true)));
  ExpectGetUserSecret();

  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), GetVersionedCredId(),
                               ArrayToSecureBlob(kCredentialSecret), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), GetVersionedCredId(),
                               GetCorrectUserSecret(), _))
      .Times(2)
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));

  auto resp = handler_->HasCredentials(request);
  EXPECT_EQ(resp.credential_id_size(), 1);
  EXPECT_EQ(resp.status(), HasCredentialsResponse::SUCCESS);
}

// Match second of the 3 types of credentials: a legacy u2f credential created
// by WebAuthnHandler, scoped to an RP ID.
TEST_F(WebAuthnHandlerTestBase, HasCredentialsMatchU2fhidWebAuthn) {
  HasCredentialsRequest request;
  request.set_rp_id(kRpId);
  request.add_credential_id(GetCredIdString());

  EXPECT_CALL(*mock_webauthn_storage_,
              GetSecretAndKeyBlobByCredentialId(GetCredIdString(), _, _))
      .WillOnce(Return(false));
  ExpectGetUserSecret();
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(GetRpIdHash(), GetCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));

  auto resp = handler_->HasCredentials(request);
  EXPECT_EQ(resp.credential_id_size(), 1);
  EXPECT_EQ(resp.status(), HasCredentialsResponse::SUCCESS);
}

// Match third of the 3 types of credentials: a legacy credential created by
// u2fhid, scoped to an App ID.
TEST_F(WebAuthnHandlerTestBase, HasCredentialsMatchAppId) {
  HasCredentialsRequest request;
  request.set_rp_id(kWrongRpId);
  request.set_app_id(kRpId);
  request.add_credential_id(GetCredIdString());

  EXPECT_CALL(*mock_webauthn_storage_,
              GetSecretAndKeyBlobByCredentialId(GetCredIdString(), _, _))
      .WillOnce(Return(false));
  ExpectGetUserSecret();
  // Matching rp_id fails.
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetWrongRpIdHash(), GetCredId(),
                               GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));
  // Matching app_id succeeds.
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(GetRpIdHash(), GetCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));

  auto resp = handler_->HasCredentials(request);
  EXPECT_EQ(resp.credential_id_size(), 1);
  EXPECT_EQ(resp.status(), HasCredentialsResponse::SUCCESS);
}

TEST_F(WebAuthnHandlerTestBase, HasCredentialsSomeMatches) {
  // Test that HasCredentials with a mix of correct and wrong length credential
  // IDs succeeds.
  HasCredentialsRequest request;
  request.set_rp_id(kRpId);
  request.set_app_id(kRpId);
  request.add_credential_id(GetVersionedCredIdString());
  std::vector<uint8_t> unknown_credential_id(U2F_V0_KH_SIZE + 1, 0xab);
  std::string unknown_credential_id_string(unknown_credential_id.begin(),
                                           unknown_credential_id.end());
  request.add_credential_id(unknown_credential_id_string);

  EXPECT_CALL(*mock_webauthn_storage_, GetSecretAndKeyBlobByCredentialId(
                                           GetVersionedCredIdString(), _, _))
      .WillOnce(DoAll(SetArgPointee<1>(ArrayToSecureBlob(kCredentialSecret)),
                      Return(true)));
  EXPECT_CALL(*mock_webauthn_storage_, GetSecretAndKeyBlobByCredentialId(
                                           unknown_credential_id_string, _, _))
      .WillOnce(Return(false));
  ExpectGetUserSecret();

  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), GetVersionedCredId(),
                               ArrayToSecureBlob(kCredentialSecret), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), GetVersionedCredId(),
                               GetCorrectUserSecret(), _))
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), unknown_credential_id,
                               GetCorrectUserSecret(), _))
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));

  auto resp = handler_->HasCredentials(request);
  EXPECT_EQ(resp.credential_id_size(), 1);
  EXPECT_EQ(resp.credential_id()[0], GetVersionedCredIdString());
  EXPECT_EQ(resp.status(), HasCredentialsResponse::SUCCESS);
}

TEST_F(WebAuthnHandlerTestBase, HasLegacyCredentialsNoMatch) {
  HasCredentialsRequest request;
  request.set_rp_id(kWrongRpId);
  request.set_app_id(kWrongRpId);
  request.add_credential_id(GetCredIdString());

  ExpectGetUserSecret();
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetWrongRpIdHash(), GetCredId(),
                               GetCorrectUserSecret(), _))
      .Times(2)
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));

  auto resp = handler_->HasLegacyCredentials(request);
  EXPECT_EQ(resp.credential_id_size(), 0);
  EXPECT_EQ(resp.status(), HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID);
}

// Match second of the 3 types of credentials.
// If rp_id matches, it's a legacy credential registered with u2fhid on WebAuthn
// API.
TEST_F(WebAuthnHandlerTestBase, HasLegacyCredentialsMatchU2fhidWebAuthn) {
  HasCredentialsRequest request;
  request.set_rp_id(kRpId);
  request.add_credential_id(GetCredIdString());

  ExpectGetUserSecret();
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(GetRpIdHash(), GetCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));

  auto resp = handler_->HasLegacyCredentials(request);
  EXPECT_EQ(resp.credential_id_size(), 1);
  EXPECT_EQ(resp.status(), HasCredentialsResponse::SUCCESS);
}

// Match third of the 3 types of credentials.
// If app_id matches, it's a legacy credential registered with U2F API.
TEST_F(WebAuthnHandlerTestBase, HasLegacyCredentialsMatchAppId) {
  HasCredentialsRequest request;
  request.set_rp_id(kWrongRpId);
  request.set_app_id(kRpId);
  request.add_credential_id(GetCredIdString());

  ExpectGetUserSecret();
  // Matching rp_id fails.
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetWrongRpIdHash(), GetCredId(),
                               GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));
  // Matching app_id succeeds.
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(GetRpIdHash(), GetCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));

  auto resp = handler_->HasLegacyCredentials(request);
  EXPECT_EQ(resp.credential_id_size(), 1);
  EXPECT_EQ(resp.status(), HasCredentialsResponse::SUCCESS);
}

TEST_F(WebAuthnHandlerTestBase, HasLegacyCredentialsSomeMatches) {
  // Test that HasLegacyCredentials with a mix of correct and wrong length
  // credential IDs succeeds.
  HasCredentialsRequest request;
  request.set_rp_id(kRpId);
  request.set_app_id(kRpId);
  request.add_credential_id(GetCredIdString());
  std::vector<uint8_t> unknown_credential_id(U2F_V0_KH_SIZE + 1, 0xab);
  std::string unknown_credential_id_string(unknown_credential_id.begin(),
                                           unknown_credential_id.end());
  request.add_credential_id(unknown_credential_id_string);

  ExpectGetUserSecret();
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(GetRpIdHash(), GetCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillRepeatedly(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), unknown_credential_id,
                               GetCorrectUserSecret(), _))
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));

  auto resp = handler_->HasLegacyCredentials(request);
  EXPECT_EQ(resp.credential_id_size(), 1);
  EXPECT_EQ(resp.credential_id()[0], GetCredIdString());
  EXPECT_EQ(resp.status(), HasCredentialsResponse::SUCCESS);
}

TEST_F(WebAuthnHandlerTestBase, MakeAuthenticatorDataWithAttestedCredData) {
  const std::vector<uint8_t> cred_id(64, 0xAA);
  const std::vector<uint8_t> cred_pubkey(65, 0xBB);

  std::vector<uint8_t> authenticator_data =
      MakeAuthenticatorData(cred_id, cred_pubkey, /* user_verified = */
                            false,
                            /* include_attested_credential_data = */ true,
                            /* is_u2f_authenticator_credential = */ false);
  EXPECT_EQ(authenticator_data.size(),
            kRpIdHashBytes + kAuthenticatorDataFlagBytes +
                kSignatureCounterBytes + kAaguidBytes +
                kCredentialIdLengthBytes + cred_id.size() + cred_pubkey.size());
  auto rp_id_hash = GetRpIdHash();
  auto aaguid = GetAaguid();
  const std::string rp_id_hash_hex =
      base::HexEncode(rp_id_hash.data(), rp_id_hash.size());
  const std::string expected_authenticator_data_regex =
      rp_id_hash_hex +  // RP ID hash
      std::string(
          "41"          // Flag: user present, attested credential data included
          "(..){4}") +  // Signature counter
      base::HexEncode(aaguid.data(), aaguid.size()) +  // AAGUID
      std::string(
          "0040"        // Credential ID length
          "(AA){64}"    // Credential ID
          "(BB){65}");  // Credential public key
  EXPECT_THAT(
      base::HexEncode(authenticator_data.data(), authenticator_data.size()),
      MatchesRegex(expected_authenticator_data_regex));
}

TEST_F(WebAuthnHandlerTestBase, MakeAuthenticatorDataNoAttestedCredData) {
  std::vector<uint8_t> authenticator_data =
      MakeAuthenticatorData(std::vector<uint8_t>(), std::vector<uint8_t>(),
                            /* user_verified = */ false,
                            /* include_attested_credential_data = */ false,
                            /* is_u2f_authenticator_credential = */ false);
  EXPECT_EQ(
      authenticator_data.size(),
      kRpIdHashBytes + kAuthenticatorDataFlagBytes + kSignatureCounterBytes);
  auto rp_id_hash = GetRpIdHash();
  const std::string rp_id_hash_hex =
      base::HexEncode(rp_id_hash.data(), rp_id_hash.size());
  const std::string expected_authenticator_data_regex =
      rp_id_hash_hex +  // RP ID hash
      std::string(
          "01"         // Flag: user present
          "(..){4}");  // Signature counter
  EXPECT_THAT(
      base::HexEncode(authenticator_data.data(), authenticator_data.size()),
      MatchesRegex(expected_authenticator_data_regex));
}

TEST_F(WebAuthnHandlerTestBase,
       MakeAuthenticatorDataU2fAuthenticatorCredential) {
  // For U2F authenticator credentials only, the counter comes from UserState.
  ExpectGetCounter();
  ExpectIncrementCounter();

  std::vector<uint8_t> authenticator_data =
      MakeAuthenticatorData(std::vector<uint8_t>(), std::vector<uint8_t>(),
                            /* user_verified = */ false,
                            /* include_attested_credential_data = */ false,
                            /* is_u2f_authenticator_credential = */ true);

  EXPECT_EQ(
      base::HexEncode(authenticator_data),
      base::HexEncode(GetRpIdHash()) +
          std::string("01"           // Flag: user present
                      "2A172A17"));  // kSignatureCounter in network byte order
}

TEST_F(WebAuthnHandlerTestBase, GetAlgorithms) {
  GetAlgorithmsRequest request;
  EXPECT_CALL(*mock_processor_, GetAlgorithm())
      .WillOnce(Return(CoseAlgorithmIdentifier::kEs256));

  auto resp = handler_->GetAlgorithms(request);
  ASSERT_EQ(resp.algorithm_size(), 1);
  EXPECT_EQ(resp.algorithm(0),
            static_cast<int32_t>(CoseAlgorithmIdentifier::kEs256));
  EXPECT_EQ(resp.status(), GetAlgorithmsResponse::SUCCESS);
}

}  // namespace

// This test fixture tests the behavior when u2f is enabled on the device.
class WebAuthnHandlerTestU2fMode : public WebAuthnHandlerTestBase {
 public:
  void SetUp() override {
    PrepareMockBus();
    CreateHandler(U2fMode::kU2f, /*allowlisting_util=*/nullptr);
    PrepareMockStorage();
  }
};

namespace {

TEST_F(WebAuthnHandlerTestU2fMode, MakeCredentialPresenceSuccess) {
  MakeCredentialRequest request;
  request.set_rp_id(kRpId);
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);

  ExpectGetCounter();
  ExpectIncrementCounter();

  // 1. LegacyCredential uses "user secret" instead of per credential secret.
  // 2. We will still check if any exclude credential matches legacy
  // credentials.
  ExpectGetUserSecretForTimes(2);
  SetUpAuthTimeSecretHash();
  EXPECT_CALL(*mock_processor_,
              U2fGenerate(GetRpIdHash(), GetCorrectUserSecret(),
                          PresenceRequirement::kPowerButton, false,
                          Pointee(GetAuthTimeSecretHash()), _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(GetCredId()),
                      SetArgPointee<6>(GetCredPubKey()),
                      Return(MakeCredentialResponse::SUCCESS)));

  // Since this creates a legacy credential with legacy secret, we won't write
  // to storage.
  EXPECT_CALL(*mock_webauthn_storage_, WriteRecord(_)).Times(0);

  EXPECT_CALL(*mock_processor_, G2fSoftwareAttest(_, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<4>(GetDummyG2fCert()),
                      SetArgPointee<5>(GetSignature()),
                      Return(MakeCredentialResponse::SUCCESS)));

  const std::string expected_authenticator_data_regex =
      base::HexEncode(GetRpIdHash()) +
      std::string(
          "41"        // Flag: user present, attested credential data included
          "2A172A17"  // kSignatureCounter in network byte order
          "(00){16}"  // AAGUID
          "0040"      // Credential ID length
                      // Credential ID, from kU2fGenerateResponse:
          "(FD){64}"  // (non-versioned) key handle
                      // CBOR encoded credential public key:
          "(AB){65}");

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<MakeCredentialResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const std::string& expected_authenticator_data,
         const MakeCredentialResponse& resp) {
        EXPECT_EQ(resp.status(), MakeCredentialResponse::SUCCESS);
        EXPECT_THAT(base::HexEncode(resp.authenticator_data().data(),
                                    resp.authenticator_data().size()),
                    MatchesRegex(expected_authenticator_data));
        EXPECT_EQ(resp.attestation_format(), "fido-u2f");
        const std::string expected_attestation_statement =
            "A2"      // Start a CBOR map of 2 elements
            "63"      // Start CBOR text of 3 chars
            "736967"  // "sig"
            ".+"      // Random signature
            "63"      // Start CBOR text of 3 chars
            "783563"  // "x5c"
            "81"      // Start CBOR array of 1 element
            ".+";     // Random x509
        EXPECT_THAT(base::HexEncode(resp.attestation_statement().data(),
                                    resp.attestation_statement().size()),
                    MatchesRegex(expected_attestation_statement));
        *called_ptr = true;
      },
      &called, expected_authenticator_data_regex));

  handler_->MakeCredential(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestU2fMode, GetAssertionSignLegacyCredentialNoPresence) {
  GetAssertionRequest request;
  request.set_rp_id(kRpId);
  request.set_client_data_hash(GetClientDataHash());
  request.add_allowed_credential_id(GetCredIdString());
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);

  ExpectGetCounter();
  ExpectIncrementCounter();

  EXPECT_CALL(*mock_webauthn_storage_,
              GetSecretAndKeyBlobByCredentialId(GetCredIdString(), _, _))
      .Times(2)
      .WillRepeatedly(Return(false));
  // LegacyCredential uses "user secret" instead of per credential secret.
  ExpectGetUserSecretForTimes(2);

  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(GetRpIdHash(), GetCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_,
              U2fSign(GetRpIdHash(), _, GetCredId(), GetCorrectUserSecret(), _,
                      PresenceRequirement::kPowerButton, _))
      .WillOnce(Return(GetAssertionResponse::VERIFICATION_FAILED));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const GetAssertionResponse& resp) {
        EXPECT_EQ(resp.status(), GetAssertionResponse::VERIFICATION_FAILED);
        *called_ptr = true;
      },
      &called));

  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestU2fMode, GetAssertionSignLegacyCredentialSuccess) {
  GetAssertionRequest request;
  request.set_rp_id(kRpId);
  request.set_client_data_hash(GetClientDataHash());
  request.add_allowed_credential_id(GetCredIdString());
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);

  ExpectGetCounter();
  ExpectIncrementCounter();

  EXPECT_CALL(*mock_webauthn_storage_,
              GetSecretAndKeyBlobByCredentialId(GetCredIdString(), _, _))
      .Times(2)
      .WillRepeatedly(Return(false));
  // LegacyCredential uses "user secret" instead of per credential secret.
  ExpectGetUserSecretForTimes(2);
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(GetRpIdHash(), GetCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_,
              U2fSign(GetRpIdHash(), _, GetCredId(), GetCorrectUserSecret(), _,
                      PresenceRequirement::kPowerButton, _))
      .WillOnce(DoAll(SetArgPointee<6>(GetSignature()),
                      Return(GetAssertionResponse::SUCCESS)));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const GetAssertionResponse& resp) {
        EXPECT_EQ(resp.status(), GetAssertionResponse::SUCCESS);
        ASSERT_EQ(resp.assertion_size(), 1);
        auto assertion = resp.assertion(0);
        EXPECT_EQ(assertion.credential_id(), GetCredIdString());
        EXPECT_EQ(
            base::HexEncode(assertion.authenticator_data().data(),
                            assertion.authenticator_data().size()),
            base::HexEncode(GetRpIdHash()) +
                std::string(
                    "01"           // Flag: user present
                    "2A172A17"));  // kSignatureCounter in network byte order
        EXPECT_EQ(util::ToVector(assertion.signature()), GetSignature());
        *called_ptr = true;
      },
      &called));

  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestU2fMode, GetAssertionSignLegacyCredentialAppIdMatch) {
  GetAssertionRequest request;
  request.set_rp_id(kWrongRpId);
  // Legacy credentials registered via U2F interface use the app id.
  request.set_app_id(kRpId);
  request.set_client_data_hash(GetClientDataHash());
  request.add_allowed_credential_id(GetCredIdString());
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);

  ExpectGetCounter();
  ExpectIncrementCounter();

  EXPECT_CALL(*mock_webauthn_storage_,
              GetSecretAndKeyBlobByCredentialId(GetCredIdString(), _, _))
      .Times(2)
      .WillRepeatedly(Return(false));
  // LegacyCredential uses "user secret" instead of per credential secret.
  ExpectGetUserSecretForTimes(2);

  // Rp id doesn't match.
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetWrongRpIdHash(), GetCredId(),
                               GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));
  // App id matches.
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(GetRpIdHash(), GetCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_,
              U2fSign(GetRpIdHash(), _, GetCredId(), GetCorrectUserSecret(), _,
                      PresenceRequirement::kPowerButton, _))
      .WillOnce(DoAll(SetArgPointee<6>(GetSignature()),
                      Return(GetAssertionResponse::SUCCESS)));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const GetAssertionResponse& resp) {
        EXPECT_EQ(resp.status(), GetAssertionResponse::SUCCESS);
        ASSERT_EQ(resp.assertion_size(), 1);
        auto assertion = resp.assertion(0);
        EXPECT_EQ(assertion.credential_id(), GetCredIdString());
        EXPECT_EQ(
            base::HexEncode(assertion.authenticator_data().data(),
                            assertion.authenticator_data().size()),
            base::HexEncode(GetRpIdHash()) +
                std::string(
                    "01"           // Flag: user present
                    "2A172A17"));  // kSignatureCounter in network byte order
        EXPECT_EQ(util::ToVector(assertion.signature()), GetSignature());
        *called_ptr = true;
      },
      &called));

  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestU2fMode,
       GetAssertionSignVersionedCredentialInUVMode) {
  // Needed for "InsertAuthTimeSecretHash" workaround.
  SetUpAuthTimeSecretHash();

  GetAssertionRequest request;
  request.set_rp_id(kRpId);
  request.set_client_data_hash(GetClientDataHash());

  request.add_allowed_credential_id(GetVersionedCredIdString());

  request.set_verification_type(
      VerificationType::VERIFICATION_USER_VERIFICATION);

  ExpectUVFlowSuccess();

  EXPECT_CALL(*mock_webauthn_storage_, GetSecretAndKeyBlobByCredentialId(
                                           GetVersionedCredIdString(), _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(ArrayToSecureBlob(kCredentialSecret)),
                Return(true)));
  ExpectGetUserSecret();
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), GetVersionedCredId(),
                               ArrayToSecureBlob(kCredentialSecret), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(_, GetVersionedCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));
  EXPECT_CALL(*mock_processor_,
              U2fSign(GetRpIdHash(), _, GetVersionedCredId(),
                      ArrayToSecureBlob(kCredentialSecret), _,
                      PresenceRequirement::kAuthorizationSecret, _))
      .WillOnce(DoAll(SetArgPointee<6>(GetSignature()),
                      Return(GetAssertionResponse::SUCCESS)));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const std::string& expected_credential_id,
         const GetAssertionResponse& resp) {
        auto rp_id_hash = GetRpIdHash();
        EXPECT_EQ(resp.status(), GetAssertionResponse::SUCCESS);
        ASSERT_EQ(resp.assertion_size(), 1);
        auto assertion = resp.assertion(0);
        EXPECT_EQ(assertion.credential_id(), expected_credential_id);
        EXPECT_THAT(
            base::HexEncode(assertion.authenticator_data().data(),
                            assertion.authenticator_data().size()),
            MatchesRegex(base::HexEncode(rp_id_hash.data(),
                                         rp_id_hash.size()) +  // RP ID hash
                         std::string("05"  // Flag: user present, user verified
                                     "(..){4}")));  // Signature counter
        EXPECT_EQ(util::ToVector(assertion.signature()), GetSignature());
        *called_ptr = true;
      },
      &called, GetVersionedCredIdString()));

  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

TEST_F(WebAuthnHandlerTestU2fMode,
       GetAssertionWithTwoTypesOfAllowedCredentials) {
  // Needed for "InsertAuthTimeSecretHash" workaround.
  SetUpAuthTimeSecretHash();

  GetAssertionRequest request;
  request.set_rp_id(kRpId);
  request.set_client_data_hash(GetClientDataHash());
  // Add a U2F credential to the allow list first.
  request.add_allowed_credential_id(GetCredIdString());
  // Add a platform credential (second type).
  request.add_allowed_credential_id(GetVersionedCredIdString());
  request.set_verification_type(
      VerificationType::VERIFICATION_USER_VERIFICATION);

  ExpectUVFlowSuccess();

  EXPECT_CALL(*mock_webauthn_storage_, GetSecretAndKeyBlobByCredentialId(
                                           GetVersionedCredIdString(), _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(ArrayToSecureBlob(kCredentialSecret)),
                Return(true)));
  EXPECT_CALL(*mock_webauthn_storage_,
              GetSecretAndKeyBlobByCredentialId(GetCredIdString(), _, _))
      .WillRepeatedly(Return(false));
  ExpectGetUserSecret();
  // Both credentials should pass U2fSignCheckOnly, but only the platform
  // credential should go through U2fSign.
  EXPECT_CALL(*mock_processor_,
              U2fSignCheckOnly(GetRpIdHash(), GetVersionedCredId(),
                               ArrayToSecureBlob(kCredentialSecret), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(_, GetVersionedCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillRepeatedly(Return(HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID));
  EXPECT_CALL(*mock_processor_, U2fSignCheckOnly(GetRpIdHash(), GetCredId(),
                                                 GetCorrectUserSecret(), _))
      .WillOnce(Return(HasCredentialsResponse::SUCCESS));

  EXPECT_CALL(*mock_processor_,
              U2fSign(GetRpIdHash(), _, GetVersionedCredId(),
                      ArrayToSecureBlob(kCredentialSecret), _,
                      PresenceRequirement::kAuthorizationSecret, _))
      .WillOnce(DoAll(SetArgPointee<6>(GetSignature()),
                      Return(GetAssertionResponse::SUCCESS)));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<GetAssertionResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const std::string& expected_credential_id,
         const GetAssertionResponse& resp) {
        auto rp_id_hash = GetRpIdHash();
        EXPECT_EQ(resp.status(), GetAssertionResponse::SUCCESS);
        ASSERT_EQ(resp.assertion_size(), 1);
        auto assertion = resp.assertion(0);
        EXPECT_EQ(assertion.credential_id(), expected_credential_id);
        EXPECT_THAT(
            base::HexEncode(assertion.authenticator_data().data(),
                            assertion.authenticator_data().size()),
            MatchesRegex(base::HexEncode(rp_id_hash.data(),
                                         rp_id_hash.size()) +  // RP ID hash
                         std::string("05"  // Flag: user present, user verified
                                     "(..){4}")));  // Signature counter
        EXPECT_EQ(util::ToVector(assertion.signature()), GetSignature());
        *called_ptr = true;
      },
      // The platform credential should appear in the assertion even though it
      // comes second in the allowed credential list.
      &called, GetVersionedCredIdString()));

  handler_->GetAssertion(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

}  // namespace

// This test fixture tests the behavior when g2f is enabled on the device.
class WebAuthnHandlerTestG2fMode : public WebAuthnHandlerTestU2fMode {
 public:
  void SetUp() override {
    PrepareMockBus();
    mock_allowlisting_util_ = new StrictMock<MockAllowlistingUtil>();
    CreateHandler(U2fMode::kU2fExtended,
                  std::unique_ptr<AllowlistingUtil>(mock_allowlisting_util_));
    PrepareMockStorage();
  }

 protected:
  StrictMock<MockAllowlistingUtil>* mock_allowlisting_util_;  // Not Owned.
};

namespace {

TEST_F(WebAuthnHandlerTestG2fMode, MakeCredentialPresenceSuccess) {
  MakeCredentialRequest request;
  request.set_rp_id(kRpId);
  request.set_verification_type(VerificationType::VERIFICATION_USER_PRESENCE);
  request.set_attestation_conveyance_preference(MakeCredentialRequest::G2F);

  ExpectGetCounter();
  ExpectIncrementCounter();

  // We will need user secret 3 times:
  // first time for u2f_generate (legacy credential),
  // second time for g2f attestation command,
  // third time for checking if any exclude credential matches legacy
  // credentials.
  ExpectGetUserSecretForTimes(3);
  SetUpAuthTimeSecretHash();
  EXPECT_CALL(*mock_processor_,
              U2fGenerate(GetRpIdHash(), _, PresenceRequirement::kPowerButton,
                          false, Pointee(GetAuthTimeSecretHash()), _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(GetCredId()),
                      SetArgPointee<6>(GetCredPubKey()),
                      Return(MakeCredentialResponse::SUCCESS)));

  // Since this creates a legacy credential with legacy secret, we won't write
  // to storage.
  EXPECT_CALL(*mock_webauthn_storage_, WriteRecord(_)).Times(0);

  // G2f attestation mock.
  EXPECT_CALL(*mock_processor_, G2fAttest(_, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<5>(GetDummyG2fCert()),
                      SetArgPointee<6>(GetSignature()),
                      Return(MakeCredentialResponse::SUCCESS)));
  EXPECT_CALL(*mock_allowlisting_util_, AppendDataToCert(_))
      .WillOnce(Return(true));

  auto mock_method_response =
      std::make_unique<MockDBusMethodResponse<MakeCredentialResponse>>();
  bool called = false;
  mock_method_response->set_return_callback(base::BindOnce(
      [](bool* called_ptr, const MakeCredentialResponse& resp) {
        EXPECT_EQ(resp.status(), MakeCredentialResponse::SUCCESS);
        EXPECT_EQ(resp.attestation_format(), "fido-u2f");
        const std::string expected_attestation_statement =
            "A2"      // Start a CBOR map of 2 elements
            "63"      // Start CBOR text of 3 chars
            "736967"  // "sig"
            ".+"      // Random signature
            "63"      // Start CBOR text of 3 chars
            "783563"  // "x5c"
            "81"      // Start CBOR array of 1 element
            ".+";     // Random x509
        EXPECT_THAT(base::HexEncode(resp.attestation_statement().data(),
                                    resp.attestation_statement().size()),
                    MatchesRegex(expected_attestation_statement));
        *called_ptr = true;
      },
      &called));

  handler_->MakeCredential(std::move(mock_method_response), request);
  ASSERT_TRUE(called);
}

}  // namespace
}  // namespace u2f
