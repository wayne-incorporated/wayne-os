// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <string>
#include <vector>

#include <attestation/proto_bindings/attestation_ca.pb.h>
#include <attestation/proto_bindings/pca_agent.pb.h>
#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback.h>
#include <base/functional/callback_helpers.h>
#include <base/run_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/synchronization/waitable_event.h>
#include <base/test/task_environment.h>
#include <brillo/data_encoding.h>
#include <brillo/errors/error.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/attestation/mock_frontend.h>
#include <libhwsec/factory/mock_factory.h>
#include <libhwsec-foundation/tpm/tpm_version.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <policy/mock_device_policy.h>
#include <policy/mock_libpolicy.h>

#include "attestation/common/mock_crypto_utility.h"
#include "attestation/common/mock_nvram_quoter.h"
#include "attestation/common/mock_tpm_utility.h"
#include "attestation/pca_agent/client/fake_pca_agent_proxy.h"
#include "attestation/server/attestation_service.h"
#include "attestation/server/google_keys.h"
#include "attestation/server/mock_database.h"
#include "attestation/server/mock_key_store.h"

using hwsec::TPMError;
using hwsec::TPMRetryAction;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::AtMost;
using testing::DoAll;
using testing::ElementsAre;
using testing::Eq;
using testing::Invoke;
using testing::NiceMock;
using testing::Return;
using testing::ReturnRef;
using testing::SetArgPointee;
using testing::StrictMock;
using testing::WithArgs;

namespace attestation {

namespace {

constexpr char kFakeIdentityKeyBlob[] = "aik key blob";
constexpr char kFakeCert[] = "fake cert";
constexpr char kFakeCaCert[] = "fake_ca_cert";
constexpr char kFakeCaCert2[] = "fake_ca_cert2";
constexpr char kFakeBoardIdQuote[] = "baord id quote";
constexpr char kFakeBoardIdQuotedData[] = "baord id quoted data";
constexpr char kFakeSnBitsQuote[] = "sn bits quote";
constexpr char kFakeSnBitsQuotedData[] = "sn bits quoted data";
constexpr char kFakeRsaEkCertQuote[] = "rsa ek cert quote";
constexpr char kFakeRsaEkCertQuotedData[] = "rsa ek cert quoted data";
constexpr char kFakeRsuDeviceIdQuote[] = "rsu device id quote";
constexpr char kFakeRsuDeviceIdQuotedData[] = "rsu device id quoted data";
constexpr char kFakeAttestedDeviceId[] = "fake device id";

struct NvramQuoteDataForTesting {
  NVRAMQuoteType type;
  const char* quote;
  const char* quoted_data;
};

class MockNvramQuoterWithFakeCertify : public MockNvramQuoter {
 public:
  MockNvramQuoterWithFakeCertify() {
    ON_CALL(*this, Certify(_, _, _))
        .WillByDefault(WithArgs<0, 2>(
            Invoke(this, &MockNvramQuoterWithFakeCertify::FakeCertify)));
  }
  ~MockNvramQuoterWithFakeCertify() override = default;

 private:
  bool FakeCertify(NVRAMQuoteType type, Quote& quote) {
    switch (type) {
      case BOARD_ID:
        quote.set_quote(kFakeBoardIdQuote);
        quote.set_quoted_data(kFakeBoardIdQuotedData);
        return true;
      case SN_BITS:
        quote.set_quote(kFakeSnBitsQuote);
        quote.set_quoted_data(kFakeSnBitsQuotedData);
        return true;
      case RSA_PUB_EK_CERT:
        quote.set_quote(kFakeRsaEkCertQuote);
        quote.set_quoted_data(kFakeRsaEkCertQuotedData);
        return true;
      case RSU_DEVICE_ID:
        quote.set_quote(kFakeRsuDeviceIdQuote);
        quote.set_quoted_data(kFakeRsuDeviceIdQuotedData);
        return true;
      default:
        return false;
    }
  }
};

TpmVersion GetTpmVersionUnderTest() {
  SET_DEFAULT_TPM_FOR_TESTING;

  TPM_SELECT_BEGIN;
  TPM1_SECTION({ return TPM_1_2; });
  TPM2_SECTION({ return TPM_2_0; });
  OTHER_TPM_SECTION();
  TPM_SELECT_END;
  return TPM_2_0;
}

std::string CreateChallenge(const std::string& prefix) {
  Challenge challenge;
  challenge.set_prefix(prefix);
  challenge.set_nonce("nonce");
  challenge.set_timestamp(100500);
  std::string serialized;
  challenge.SerializeToString(&serialized);
  return serialized;
}

std::string CreateSignedChallenge(const std::string& prefix) {
  SignedData signed_data;
  signed_data.set_data(CreateChallenge(prefix));
  signed_data.set_signature("challenge_signature");
  std::string serialized;
  signed_data.SerializeToString(&serialized);
  return serialized;
}

EncryptedData MockEncryptedData(std::string data) {
  EncryptedData encrypted_data;
  encrypted_data.set_wrapped_key("wrapped_key");
  encrypted_data.set_iv("iv");
  encrypted_data.set_mac("mac");
  encrypted_data.set_encrypted_data(data);
  encrypted_data.set_wrapping_key_id("wrapping_key_id");
  return encrypted_data;
}

KeyInfo CreateChallengeKeyInfo(std::string customer_id = "") {
  KeyInfo key_info;
  key_info.set_flow_type(ENTERPRISE_USER);
  key_info.set_domain("domain");
  key_info.set_device_id("device_id");
  key_info.set_certificate("");
  if (!customer_id.empty()) {
    key_info.set_customer_id(customer_id);
  }
  return key_info;
}

KeyInfo CreateMachineChallengeKeyInfoWithSPKAC(
    const std::string& certified_credential_of_key_for_spkac,
    const std::string& spkac) {
  // Create a PEM encoding of |certified_credential_of_key_for_spkac|.
  std::string pem_certificate_of_key_for_spkac =
      "-----BEGIN CERTIFICATE-----\n" +
      brillo::data_encoding::Base64EncodeWrapLines(
          certified_credential_of_key_for_spkac) +
      "-----END CERTIFICATE-----";

  KeyInfo key_info;
  key_info.set_flow_type(ENTERPRISE_MACHINE);
  key_info.set_customer_id("customer_id");
  key_info.set_device_id("device_id");
  key_info.set_certificate(pem_certificate_of_key_for_spkac);
  key_info.set_signed_public_key_and_challenge(spkac);
  return key_info;
}

std::string GetFakeCertificateChain() {
  const std::string kBeginCertificate = "-----BEGIN CERTIFICATE-----\n";
  const std::string kEndCertificate = "-----END CERTIFICATE-----";
  std::string pem = kBeginCertificate;
  pem += brillo::data_encoding::Base64EncodeWrapLines(kFakeCert);
  pem += kEndCertificate + "\n" + kBeginCertificate;
  pem += brillo::data_encoding::Base64EncodeWrapLines(kFakeCaCert);
  pem += kEndCertificate + "\n" + kBeginCertificate;
  pem += brillo::data_encoding::Base64EncodeWrapLines(kFakeCaCert2);
  pem += kEndCertificate;
  return pem;
}

// testing::InvokeArgument<N> does not work with base::Callback, need to use
// |ACTION_TAMPLATE| along with predefined |args| tuple.
ACTION_TEMPLATE(InvokeCallbackArgument,
                HAS_1_TEMPLATE_PARAMS(int, k),
                AND_1_VALUE_PARAMS(p0)) {
  std::get<k>(args).Run(p0);
}

}  // namespace

class AttestationServiceBaseTest : public testing::Test {
 public:
  ~AttestationServiceBaseTest() override = default;

  void SetUp() override {
    SET_DEFAULT_TPM_FOR_TESTING;
    service_.reset(new AttestationService(nullptr, ""));
    service_->set_database(&mock_database_);
    service_->set_hwsec_factory(&mock_hwsec_factory_);
    service_->set_hwsec(&mock_hwsec_);
    service_->set_crypto_utility(&mock_crypto_utility_);
    service_->set_key_store(&mock_key_store_);
    service_->set_tpm_utility(&mock_tpm_utility_);
    service_->set_nvram_quoter(&mock_nvram_quoter_);
    service_->set_hwid("fake_hwid");
    service_->set_pca_agent_proxy(&fake_pca_agent_proxy_);
    mock_policy_provider_ = new StrictMock<policy::MockPolicyProvider>();
    service_->set_policy_provider(mock_policy_provider_);
    // Setup a fake wrapped EK certificate by default.
    (*mock_database_.GetMutableProtobuf()
          ->mutable_credentials()
          ->mutable_encrypted_endorsement_credentials())[DEFAULT_ACA]
        .set_wrapping_key_id("default");
    (*mock_database_.GetMutableProtobuf()
          ->mutable_credentials()
          ->mutable_encrypted_endorsement_credentials())[TEST_ACA]
        .set_wrapping_key_id("test");
    Quote fake_quote;
    fake_quote.set_quoted_pcr_value("");
    EXPECT_CALL(mock_hwsec_, Quote).WillRepeatedly(ReturnValue(fake_quote));
    hwsec::DeviceConfigSettings::BootModeSetting::Mode fake_mode = {
        .developer_mode = false,
        .recovery_mode = false,
        .verified_firmware = false,
    };
    EXPECT_CALL(mock_hwsec_, GetCurrentBootMode)
        .WillRepeatedly(ReturnValue(fake_mode));
    // Run out initialize task(s) to avoid any race conditions with tests that
    // need to change the default setup.
    CHECK(
        CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                   base::Unretained(service_.get()))));
  }

 protected:
  void Run() { run_loop_.Run(); }

  void RunUntilIdle() { run_loop_.RunUntilIdle(); }

  void Quit() { run_loop_.Quit(); }

  base::RepeatingClosure QuitClosure() { return run_loop_.QuitClosure(); }

  template <typename T>
  T CallAndWait(
      base::OnceCallback<T(AttestationService::InitializeCompleteCallback)>
          func) {
    base::WaitableEvent done(base::WaitableEvent::ResetPolicy::AUTOMATIC,
                             base::WaitableEvent::InitialState::NOT_SIGNALED);
    T val = std::move(func).Run(
        base::BindOnce([](base::WaitableEvent* done, bool) { done->Signal(); },
                       base::Unretained(&done)));
    done.Wait();
    return val;
  }

  void SetUpIdentity(int identity) {
    auto* database = mock_database_.GetMutableProtobuf();
    AttestationDatabase::Identity* identity_data;
    if (database->identities().size() > identity) {
      identity_data = database->mutable_identities()->Mutable(identity);
    } else {
      for (int i = database->identities().size(); i <= identity; ++i) {
        identity_data = database->mutable_identities()->Add();
      }
    }
    identity_data->set_features(IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID);
    identity_data->mutable_identity_key()->set_identity_public_key_der(
        "public_key");
    identity_data->mutable_identity_key()->set_identity_key_blob(
        kFakeIdentityKeyBlob);
    identity_data->mutable_identity_binding()
        ->set_identity_public_key_tpm_format("public_key_tpm");
    (*identity_data->mutable_pcr_quotes())[0].set_quote("pcr0");
    (*identity_data->mutable_pcr_quotes())[1].set_quote("pcr1");
    (*identity_data->mutable_nvram_quotes())[BOARD_ID].set_quote(
        kFakeBoardIdQuote);
    (*identity_data->mutable_nvram_quotes())[BOARD_ID].set_quoted_data(
        kFakeBoardIdQuotedData);
    (*identity_data->mutable_nvram_quotes())[SN_BITS].set_quote(
        kFakeSnBitsQuote);
    (*identity_data->mutable_nvram_quotes())[SN_BITS].set_quoted_data(
        kFakeSnBitsQuotedData);
    if (service_->GetEndorsementKeyType() !=
        kEndorsementKeyTypeForEnrollmentID) {
      (*identity_data->mutable_nvram_quotes())[RSA_PUB_EK_CERT].set_quote(
          kFakeRsaEkCertQuote);
      (*identity_data->mutable_nvram_quotes())[RSA_PUB_EK_CERT].set_quoted_data(
          kFakeRsaEkCertQuotedData);
    }
  }

  void RemoveNvramQuotesFromIdentity(int identity) {
    auto* database = mock_database_.GetMutableProtobuf();
    AttestationDatabase::Identity* identity_data;
    ASSERT_GT(database->identities().size(), identity);
    identity_data = database->mutable_identities()->Mutable(identity);
    identity_data->clear_nvram_quotes();
    ASSERT_EQ(database->mutable_identities()
                  ->Mutable(identity)
                  ->nvram_quotes()
                  .size(),
              0);
  }

  // Generate a unique name for a certificate from an ACA.
  std::string GetCertificateName(int identity, ACAType aca_type) {
    std::ostringstream stream;
    stream << "certificate(" << identity << ", " << aca_type << ")";
    return stream.str();
  }

  // Create an identity certificate if needed and sets an ACA-signed
  // certificate. Once this exists, we consider that the identity has been
  // enrolled with the given ACA.
  void SetUpIdentityCertificate(int identity, ACAType aca_type) {
    auto identity_certificate = service_->FindOrCreateIdentityCertificate(
        identity, aca_type, nullptr /* cert_index */);
    EXPECT_NE(nullptr, identity_certificate);
    identity_certificate->set_identity_credential(
        GetCertificateName(identity, aca_type));
  }

  CertifiedKey GenerateFakeCertifiedKey() const {
    CertifiedKey key;
    key.set_public_key("public_key");
    key.set_certified_key_credential(kFakeCert);
    key.set_intermediate_ca_cert(kFakeCaCert);
    *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
    key.set_key_name("label");
    key.set_certified_key_info("certify_info");
    key.set_certified_key_proof("signature");
    key.set_key_type(KEY_TYPE_RSA);
    key.set_key_usage(KEY_USAGE_SIGN);
    return key;
  }

  std::string GenerateSerializedFakeCertifiedKey() const {
    CertifiedKey key = GenerateFakeCertifiedKey();
    return key.SerializeAsString();
  }

  void ExpectGetCustomerId(std::string customer_id) {
    EXPECT_CALL(*mock_policy_provider_, Reload()).WillOnce(Return(true));
    EXPECT_CALL(*mock_policy_provider_, device_policy_is_loaded())
        .WillOnce(Return(true));
    EXPECT_CALL(*mock_policy_provider_, GetDevicePolicy())
        .WillOnce(ReturnRef(mock_device_policy_));
    if (customer_id.empty()) {
      // Assume empty means a customer ID is not available.
      EXPECT_CALL(mock_device_policy_, GetCustomerId(_))
          .WillOnce(Return(false));
    } else {
      EXPECT_CALL(mock_device_policy_, GetCustomerId(_))
          .WillOnce(DoAll(SetArgPointee<0>(customer_id), Return(true)));
    }
  }

  // Verify Attestation CA-related data, including the default CA's identity
  // credential.
  void VerifyACAData(const AttestationDatabase& db,
                     const char* default_identity_credential) {
    ASSERT_EQ(default_identity_credential ? 1 : 0,
              db.identity_certificates().size());
    for (int aca = 0; aca < db.identity_certificates().size(); ++aca) {
      const AttestationDatabase::IdentityCertificate identity_certificate =
          db.identity_certificates().at(aca);
      ASSERT_EQ(0, identity_certificate.identity());
      ASSERT_EQ(aca, identity_certificate.aca());
      if (default_identity_credential && aca == DEFAULT_ACA) {
        ASSERT_EQ(default_identity_credential,
                  identity_certificate.identity_credential());
      } else {
        ASSERT_FALSE(identity_certificate.has_identity_credential());
      }
    }
    // All ACAs have encrypted credentials.
    for (int aca = AttestationService::kDefaultACA;
         aca < AttestationService::kMaxACATypeInternal; ++aca) {
      AttestationService::ACATypeInternal aca_int =
          static_cast<AttestationService::ACATypeInternal>(aca);
      ASSERT_TRUE(db.credentials().encrypted_endorsement_credentials().count(
          AttestationService::GetACAType(aca_int)));
    }
  }

  // Verify Attestation CA-related data, including the lack of default CA's
  // identity credential.
  void VerifyACAData(const AttestationDatabase& db) {
    VerifyACAData(db, nullptr);
  }

  std::string ComputeEnterpriseEnrollmentId() {
    return service_->ComputeEnterpriseEnrollmentId();
  }

  std::string GetEnrollmentId() {
    GetEnrollmentIdRequest request;
    auto result = std::make_shared<GetEnrollmentIdReply>();
    service_->GetEnrollmentIdTask(request, result);
    if (result->status() != STATUS_SUCCESS) {
      return "";
    }

    return result->enrollment_id();
  }

  NiceMock<MockCryptoUtility> mock_crypto_utility_;
  NiceMock<MockDatabase> mock_database_;
  NiceMock<MockKeyStore> mock_key_store_;
  NiceMock<MockTpmUtility> mock_tpm_utility_;
  NiceMock<hwsec::MockAttestationFrontend> mock_hwsec_;
  NiceMock<hwsec::MockFactory> mock_hwsec_factory_;
  StrictMock<MockNvramQuoterWithFakeCertify> mock_nvram_quoter_;
  StrictMock<policy::MockPolicyProvider>* mock_policy_provider_;  // Not Owned.
  StrictMock<policy::MockDevicePolicy> mock_device_policy_;
  StrictMock<pca_agent::client::FakePcaAgentProxy> fake_pca_agent_proxy_{
      GetTpmVersionUnderTest()};
  std::unique_ptr<AttestationService> service_;
  const int identity_ = AttestationService::kFirstIdentity;

 private:
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::ThreadingMode::MAIN_THREAD_ONLY};
  base::RunLoop run_loop_;
};

TEST_F(AttestationServiceBaseTest, GetFeatures) {
  EXPECT_CALL(mock_tpm_utility_, GetSupportedKeyTypes())
      .WillOnce(Return(std::vector<KeyType>{KEY_TYPE_RSA, KEY_TYPE_ECC}));
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetFeaturesReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    EXPECT_THAT(reply.supported_key_types(),
                ElementsAre(KEY_TYPE_RSA, KEY_TYPE_ECC));
    quit_closure.Run();
  };

  GetFeaturesRequest request;
  service_->GetFeatures(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, MigrateAttestationDatabase) {
  // Simulate an older database.
  auto* db = mock_database_.GetMutableProtobuf();
  db->mutable_credentials()->clear_encrypted_endorsement_credentials();
  db->mutable_credentials()->set_endorsement_credential("endorsement_cred");
  EncryptedData default_encrypted_endorsement_credential;
  default_encrypted_endorsement_credential.set_wrapped_key("default_key");
  db->mutable_credentials()
      ->mutable_default_encrypted_endorsement_credential()
      ->CopyFrom(default_encrypted_endorsement_credential);
  db->clear_identities();
  db->clear_identity_certificates();
  db->mutable_identity_binding()->set_identity_binding("identity_binding");
  db->mutable_identity_binding()->set_identity_public_key_tpm_format(
      "identity_public_key");
  db->mutable_identity_key()->set_identity_credential("identity_cred");
  db->mutable_pcr0_quote()->set_quote("pcr0_quote");
  db->mutable_pcr1_quote()->set_quote("pcr1_quote");
  // Persist that older database.
  mock_database_.SaveChanges();

  // Simulate login.
  CHECK(CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                   base::Unretained(service_.get()))));
  service_->PrepareForEnrollment(base::DoNothing());

  const auto& const_db = mock_database_.GetProtobuf();
  // The default encrypted endorsement credential has been migrated.
  // The deprecated field has not been cleared so that older code can still
  // use the database.
  EXPECT_EQ(default_encrypted_endorsement_credential.wrapped_key(),
            const_db.credentials()
                .encrypted_endorsement_credentials()
                .at(DEFAULT_ACA)
                .wrapped_key());
  EXPECT_EQ(default_encrypted_endorsement_credential.wrapped_key(),
            const_db.credentials()
                .default_encrypted_endorsement_credential()
                .wrapped_key());

  // The default identity has data copied from the deprecated database fields.
  // The deprecated fields have not been cleared so that older code can still
  // use the database.
  const AttestationDatabase::Identity& default_identity_data =
      const_db.identities().Get(DEFAULT_ACA);
  EXPECT_EQ(IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID,
            default_identity_data.features());
  EXPECT_EQ("identity_binding",
            default_identity_data.identity_binding().identity_binding());
  EXPECT_EQ("identity_public_key", default_identity_data.identity_binding()
                                       .identity_public_key_tpm_format());
  EXPECT_EQ("identity_binding", const_db.identity_binding().identity_binding());
  EXPECT_EQ("identity_public_key",
            const_db.identity_binding().identity_public_key_tpm_format());
  EXPECT_EQ("pcr0_quote", default_identity_data.pcr_quotes().at(0).quote());
  EXPECT_EQ("pcr0_quote", const_db.pcr0_quote().quote());
  EXPECT_EQ("pcr1_quote", default_identity_data.pcr_quotes().at(1).quote());
  EXPECT_EQ("pcr1_quote", const_db.pcr1_quote().quote());

  // No other identity has been created.
  EXPECT_EQ(1, const_db.identities().size());

  // The identity credential was migrated into an identity certificate.
  // As a result, identity data does not use the identity credential. The
  // deprecated field has not been cleared so that older code can still
  // use the database.
  EXPECT_FALSE(default_identity_data.identity_key().has_identity_credential());
  EXPECT_EQ("identity_cred", const_db.identity_key().identity_credential());
  VerifyACAData(const_db, "identity_cred");
}

TEST_F(AttestationServiceBaseTest,
       MigrateAttestationDatabaseWithCorruptedFields) {
  // Simulate an older database.
  auto* db = mock_database_.GetMutableProtobuf();
  db->mutable_credentials()->clear_encrypted_endorsement_credentials();
  db->mutable_credentials()->set_endorsement_credential("endorsement_cred");
  EncryptedData default_encrypted_endorsement_credential;
  default_encrypted_endorsement_credential.set_wrapped_key("default_key");
  db->mutable_credentials()
      ->mutable_default_encrypted_endorsement_credential()
      ->CopyFrom(default_encrypted_endorsement_credential);
  db->clear_identities();
  db->clear_identity_certificates();
  db->mutable_identity_binding()->set_identity_binding("identity_binding");
  db->mutable_identity_binding()->set_identity_public_key_tpm_format(
      "identity_public_key");
  db->mutable_identity_key()->set_identity_credential("identity_cred");
  // Note that we are missing a PCR0 quote.
  db->mutable_pcr1_quote()->set_quote("pcr1_quote");
  // Persist that older database.
  mock_database_.SaveChanges();

  // Simulate login.
  CHECK(CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                   base::Unretained(service_.get()))));
  service_->PrepareForEnrollment(base::DoNothing());

  const auto& const_db = mock_database_.GetProtobuf();
  // The default encrypted endorsement credential has been migrated.
  // The deprecated field has not been cleared so that older code can still
  // use the database.
  EXPECT_EQ(default_encrypted_endorsement_credential.wrapped_key(),
            const_db.credentials()
                .encrypted_endorsement_credentials()
                .at(DEFAULT_ACA)
                .wrapped_key());
  EXPECT_EQ(default_encrypted_endorsement_credential.wrapped_key(),
            const_db.credentials()
                .default_encrypted_endorsement_credential()
                .wrapped_key());

  // The default identity could not be copied from the deprecated database.
  // The deprecated fields have not been cleared so that older code can still
  // use the database.
  ASSERT_TRUE(const_db.identities().empty());
  ASSERT_EQ("identity_binding", const_db.identity_binding().identity_binding());
  ASSERT_EQ("identity_public_key",
            const_db.identity_binding().identity_public_key_tpm_format());
  EXPECT_EQ("pcr1_quote", const_db.pcr1_quote().quote());

  // There is no identity certificate since there is no identity.
  ASSERT_TRUE(const_db.identity_certificates().empty());
}

TEST_F(AttestationServiceBaseTest,
       MigrateAttestationDatabaseAllEndorsementCredentials) {
  // Simulate an older database.
  auto* db = mock_database_.GetMutableProtobuf();
  db->mutable_credentials()->clear_encrypted_endorsement_credentials();
  db->mutable_credentials()->set_endorsement_credential("endorsement_cred");
  EncryptedData default_encrypted_endorsement_credential;
  default_encrypted_endorsement_credential.set_wrapped_key("default_key");
  db->mutable_credentials()
      ->mutable_default_encrypted_endorsement_credential()
      ->CopyFrom(default_encrypted_endorsement_credential);
  EncryptedData test_encrypted_endorsement_credential;
  test_encrypted_endorsement_credential.set_wrapped_key("test_key");
  db->mutable_credentials()
      ->mutable_test_encrypted_endorsement_credential()
      ->CopyFrom(test_encrypted_endorsement_credential);
  db->clear_identities();
  db->clear_identity_certificates();
  db->mutable_identity_binding()->set_identity_binding("identity_binding");
  db->mutable_identity_binding()->set_identity_public_key_tpm_format(
      "identity_public_key");
  db->mutable_identity_key()->set_identity_credential("identity_cred");
  db->mutable_pcr0_quote()->set_quote("pcr0_quote");
  db->mutable_pcr1_quote()->set_quote("pcr1_quote");
  // Persist that older database.
  mock_database_.SaveChanges();

  // Simulate second login.
  CHECK(CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                   base::Unretained(service_.get()))));
  service_->PrepareForEnrollment(base::DoNothing());

  const auto& const_db = mock_database_.GetProtobuf();
  // The encrypted endorsement credentials have both been migrated.
  // The deprecated fields have not been cleared so that older code can still
  // use the database.
  EXPECT_EQ(default_encrypted_endorsement_credential.wrapped_key(),
            const_db.credentials()
                .encrypted_endorsement_credentials()
                .at(DEFAULT_ACA)
                .wrapped_key());
  EXPECT_EQ(default_encrypted_endorsement_credential.wrapped_key(),
            const_db.credentials()
                .default_encrypted_endorsement_credential()
                .wrapped_key());
  EXPECT_EQ(test_encrypted_endorsement_credential.wrapped_key(),
            const_db.credentials()
                .encrypted_endorsement_credentials()
                .at(TEST_ACA)
                .wrapped_key());
  EXPECT_EQ(test_encrypted_endorsement_credential.wrapped_key(),
            const_db.credentials()
                .test_encrypted_endorsement_credential()
                .wrapped_key());
}

TEST_F(AttestationServiceBaseTest, GetEndorsementInfoNoInfo) {
  EXPECT_CALL(mock_tpm_utility_, GetEndorsementPublicKey(_, _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const GetEndorsementInfoReply& reply) {
    EXPECT_EQ(STATUS_NOT_AVAILABLE, reply.status());
    EXPECT_FALSE(reply.has_ek_public_key());
    EXPECT_FALSE(reply.has_ek_certificate());
    std::move(quit_closure).Run();
  };
  GetEndorsementInfoRequest request;
  service_->GetEndorsementInfo(request,
                               base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, GetEndorsementInfoNoCert) {
  EXPECT_CALL(mock_tpm_utility_, GetEndorsementCertificate(_, _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const GetEndorsementInfoReply& reply) {
    EXPECT_EQ(STATUS_UNEXPECTED_DEVICE_ERROR, reply.status());
    EXPECT_FALSE(reply.has_ek_public_key());
    EXPECT_FALSE(reply.has_ek_certificate());
    std::move(quit_closure).Run();
  };
  GetEndorsementInfoRequest request;
  service_->GetEndorsementInfo(request,
                               base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, GetKeyInfoSuccess) {
  // Setup a certified key in the key store.
  CertifiedKey key;
  key.set_public_key("public_key");
  key.set_certified_key_credential(kFakeCert);
  key.set_intermediate_ca_cert(kFakeCaCert);
  *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
  key.set_key_name("label");
  key.set_certified_key_info("certify_info");
  key.set_certified_key_proof("signature");
  key.set_key_type(KEY_TYPE_RSA);
  key.set_key_usage(KEY_USAGE_SIGN);
  std::string key_bytes;
  key.SerializeToString(&key_bytes);
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(DoAll(SetArgPointee<2>(key_bytes), Return(true)));

  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const GetKeyInfoReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(KEY_TYPE_RSA, reply.key_type());
    EXPECT_EQ(KEY_USAGE_SIGN, reply.key_usage());
    EXPECT_EQ("public_key", reply.public_key());
    EXPECT_EQ("certify_info", reply.certify_info());
    EXPECT_EQ("signature", reply.certify_info_signature());
    EXPECT_EQ(kFakeCert, reply.certified_key_credential());
    EXPECT_EQ(GetFakeCertificateChain(), reply.certificate());
    std::move(quit_closure).Run();
  };
  GetKeyInfoRequest request;
  request.set_key_label("label");
  request.set_username("user");
  service_->GetKeyInfo(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, GetKeyInfoSuccessNoUser) {
  // Setup a certified key in the device key store.
  CertifiedKey& key = *mock_database_.GetMutableProtobuf()->add_device_keys();
  key.set_public_key("public_key");
  key.set_certified_key_credential(kFakeCert);
  key.set_intermediate_ca_cert(kFakeCaCert);
  *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
  key.set_key_name("label");
  key.set_certified_key_info("certify_info");
  key.set_certified_key_proof("signature");
  key.set_key_type(KEY_TYPE_RSA);
  key.set_key_usage(KEY_USAGE_SIGN);

  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const GetKeyInfoReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(KEY_TYPE_RSA, reply.key_type());
    EXPECT_EQ(KEY_USAGE_SIGN, reply.key_usage());
    EXPECT_EQ("public_key", reply.public_key());
    EXPECT_EQ("certify_info", reply.certify_info());
    EXPECT_EQ("signature", reply.certify_info_signature());
    EXPECT_EQ(kFakeCert, reply.certified_key_credential());
    EXPECT_EQ(GetFakeCertificateChain(), reply.certificate());
    std::move(quit_closure).Run();
  };
  GetKeyInfoRequest request;
  request.set_key_label("label");
  service_->GetKeyInfo(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, GetKeyInfoNoKey) {
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillRepeatedly(Return(false));

  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const GetKeyInfoReply& reply) {
    EXPECT_EQ(STATUS_INVALID_PARAMETER, reply.status());
    std::move(quit_closure).Run();
  };
  GetKeyInfoRequest request;
  request.set_key_label("label");
  request.set_username("user");
  service_->GetKeyInfo(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, GetKeyInfoBadPublicKey) {
  EXPECT_CALL(mock_crypto_utility_, GetRSASubjectPublicKeyInfo(_, _))
      .WillRepeatedly(Return(false));

  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const GetKeyInfoReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  GetKeyInfoRequest request;
  request.set_key_label("label");
  request.set_username("user");
  service_->GetKeyInfo(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, GetEndorsementKeyTypeForExistingKey) {
  AttestationDatabase* database = mock_database_.GetMutableProtobuf();
  // Default key type is KEY_TYPE_RSA.
  database->mutable_credentials()->set_endorsement_public_key("public_key");
  database->mutable_credentials()->set_endorsement_credential("certificate");
  EXPECT_EQ(service_->GetEndorsementKeyType(), KEY_TYPE_RSA);

  database->mutable_credentials()->set_endorsement_key_type(KEY_TYPE_ECC);
  database->mutable_credentials()->set_endorsement_public_key("public_key");
  database->mutable_credentials()->set_endorsement_credential("certificate");
  EXPECT_EQ(service_->GetEndorsementKeyType(), KEY_TYPE_ECC);
}

TEST_F(AttestationServiceBaseTest, GetEndorsementKeyTypeForNewlyCreatedKey) {
  EXPECT_EQ(service_->GetEndorsementKeyType(), kDefaultEndorsementKeyType);
}

TEST_F(AttestationServiceBaseTest, GetAttestationIdentityKeyType) {
  EXPECT_EQ(service_->GetAttestationIdentityKeyType(), kDefaultIdentityKeyType);
}

TEST_F(AttestationServiceBaseTest, GetEndorsementInfoSuccess) {
  AttestationDatabase* database = mock_database_.GetMutableProtobuf();
  database->mutable_credentials()->set_endorsement_public_key("public_key");
  database->mutable_credentials()->set_endorsement_credential("certificate");
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const GetEndorsementInfoReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ("public_key", reply.ek_public_key());
    EXPECT_EQ("certificate", reply.ek_certificate());
    std::move(quit_closure).Run();
  };
  GetEndorsementInfoRequest request;
  service_->GetEndorsementInfo(request,
                               base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, GetEnrollmentId) {
  EXPECT_CALL(mock_tpm_utility_, GetEndorsementPublicKeyBytes(_, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(std::string("ekm")), Return(true)));
  brillo::SecureBlob abe_data(0xCA, 32);
  service_->set_abe_data(&abe_data);
  CryptoUtilityImpl crypto_utility(&mock_tpm_utility_, &mock_hwsec_);
  service_->set_crypto_utility(&crypto_utility);
  std::string enrollment_id = GetEnrollmentId();
  EXPECT_EQ("635c4526dfa583362273e2987944007b09131cfa0f4e5874e7a76d55d333e3cc",
            base::ToLowerASCII(
                base::HexEncode(enrollment_id.data(), enrollment_id.size())));

  // Cache the EID in the database.
  AttestationDatabase database_pb;
  database_pb.set_enrollment_id(enrollment_id);
  EXPECT_CALL(mock_database_, GetProtobuf()).WillOnce(ReturnRef(database_pb));

  // Change abe_data, and yet the EID remains the same.
  brillo::SecureBlob abe_data_new(0x89, 32);
  service_->set_abe_data(&abe_data_new);
  enrollment_id = GetEnrollmentId();
  EXPECT_EQ("635c4526dfa583362273e2987944007b09131cfa0f4e5874e7a76d55d333e3cc",
            base::ToLowerASCII(
                base::HexEncode(enrollment_id.data(), enrollment_id.size())));
}

TEST_F(AttestationServiceBaseTest, SignSimpleChallengeSuccess) {
  EXPECT_CALL(mock_tpm_utility_, Sign(_, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(std::string("signature")), Return(true)));
  auto callback = [](base::OnceClosure quit_closure,
                     const SignSimpleChallengeReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_challenge_response());
    SignedData signed_data;
    EXPECT_TRUE(signed_data.ParseFromString(reply.challenge_response()));
    EXPECT_EQ("signature", signed_data.signature());
    EXPECT_EQ(0, signed_data.data().find("challenge"));
    EXPECT_NE("challenge", signed_data.data());
    std::move(quit_closure).Run();
  };
  SignSimpleChallengeRequest request;
  request.set_username("user");
  request.set_key_label("label");
  request.set_challenge("challenge");
  service_->SignSimpleChallenge(request,
                                base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, SignSimpleChallengeInternalFailure) {
  EXPECT_CALL(mock_tpm_utility_, Sign(_, _, _)).WillRepeatedly(Return(false));
  auto callback = [](base::OnceClosure quit_closure,
                     const SignSimpleChallengeReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_challenge_response());
    std::move(quit_closure).Run();
  };
  SignSimpleChallengeRequest request;
  request.set_username("user");
  request.set_key_label("label");
  request.set_challenge("challenge");
  service_->SignSimpleChallenge(request,
                                base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_F(AttestationServiceBaseTest, VerifyCertificateWithSubjectPublicKeyInfo) {
  std::string issuer = "Infineon OPTIGA(TM) TPM 2.0 ECC CA 055";
  std::string issuer_with_multiple_keys = "CROS D2 CIK";
  std::string invalid_issuer = "INVALID ISSUER";
  std::string ek_cert = "";  // not used

  // It should return fail because is_cros_core is true
  EXPECT_CALL(mock_crypto_utility_, VerifyCertificateWithSubjectPublicKey)
      .Times(0);
  EXPECT_FALSE(service_->VerifyCertificateWithSubjectPublicKeyInfo(issuer, true,
                                                                   ek_cert));

  // Test issuer with single key
  EXPECT_CALL(mock_crypto_utility_, VerifyCertificateWithSubjectPublicKey)
      .WillOnce(Return(true));
  EXPECT_TRUE(service_->VerifyCertificateWithSubjectPublicKeyInfo(issuer, false,
                                                                  ek_cert));

  EXPECT_CALL(mock_crypto_utility_, VerifyCertificateWithSubjectPublicKey)
      .WillOnce(Return(false));
  EXPECT_FALSE(service_->VerifyCertificateWithSubjectPublicKeyInfo(
      issuer, false, ek_cert));

  // Test issuer with multiple keys
  EXPECT_CALL(mock_crypto_utility_, VerifyCertificateWithSubjectPublicKey)
      .WillOnce(Return(false))
      .WillOnce(Return(true));
  EXPECT_TRUE(service_->VerifyCertificateWithSubjectPublicKeyInfo(
      issuer_with_multiple_keys, false, ek_cert));

  EXPECT_CALL(mock_crypto_utility_, VerifyCertificateWithSubjectPublicKey)
      .WillRepeatedly(Return(false));
  EXPECT_FALSE(service_->VerifyCertificateWithSubjectPublicKeyInfo(
      issuer_with_multiple_keys, false, ek_cert));

  // Test issuer that is not on the list
  EXPECT_CALL(mock_crypto_utility_, VerifyCertificateWithSubjectPublicKey)
      .Times(0);
  EXPECT_FALSE(service_->VerifyCertificateWithSubjectPublicKeyInfo(
      invalid_issuer, false, ek_cert));
}

class AttestationServiceEnterpriseTest
    : public AttestationServiceBaseTest,
      public testing::WithParamInterface<VAType> {
 public:
  AttestationServiceEnterpriseTest() : va_type_(GetParam()) {}
  ~AttestationServiceEnterpriseTest() override = default;

 protected:
  VAType va_type_;
  // A default GoogleKeys instance that is supposed to be the identical key
  // database that |service_| uses.
  GoogleKeys google_keys_;
};

TEST_P(AttestationServiceEnterpriseTest, SignEnterpriseChallengeSuccess) {
  KeyInfo key_info = CreateChallengeKeyInfo();
  std::string key_info_str;
  key_info.SerializeToString(&key_info_str);
  EXPECT_CALL(
      mock_crypto_utility_,
      VerifySignatureUsingHexKey(
          _, google_keys_.va_signing_key(va_type_).modulus_in_hex(), _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(
      mock_crypto_utility_,
      EncryptDataForGoogle(
          key_info_str,
          google_keys_.va_encryption_key(va_type_).modulus_in_hex(), _, _))
      .WillRepeatedly(DoAll(SetArgPointee<3>(MockEncryptedData(key_info_str)),
                            Return(true)));
  EXPECT_CALL(mock_tpm_utility_, Sign(_, _, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<2>(std::string("signature")), Return(true)));
  auto callback = [](base::OnceClosure quit_closure,
                     const SignEnterpriseChallengeReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_challenge_response());
    SignedData signed_data;
    EXPECT_TRUE(signed_data.ParseFromString(reply.challenge_response()));
    EXPECT_EQ("signature", signed_data.signature());
    ChallengeResponse response_pb;
    EXPECT_TRUE(response_pb.ParseFromString(signed_data.data()));
    EXPECT_EQ(CreateChallenge("EnterpriseKeyChallenge"),
              response_pb.challenge().data());
    KeyInfo key_info = CreateChallengeKeyInfo();
    std::string key_info_str;
    key_info.SerializeToString(&key_info_str);
    EXPECT_EQ(key_info_str, response_pb.encrypted_key_info().encrypted_data());
    std::move(quit_closure).Run();
  };
  SignEnterpriseChallengeRequest request;
  request.set_va_type(va_type_);
  request.set_username("user");
  request.set_key_label("label");
  request.set_domain(key_info.domain());
  request.set_device_id(key_info.device_id());
  request.set_include_signed_public_key(false);
  request.set_challenge(CreateSignedChallenge("EnterpriseKeyChallenge"));
  service_->SignEnterpriseChallenge(request,
                                    base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceEnterpriseTest,
       SignEnterpriseChallengeInternalFailure) {
  KeyInfo key_info = CreateChallengeKeyInfo();
  std::string key_info_str;
  key_info.SerializeToString(&key_info_str);
  EXPECT_CALL(mock_crypto_utility_, VerifySignatureUsingHexKey(_, _, _, _))
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_tpm_utility_, Sign(_, _, _)).WillRepeatedly(Return(false));
  auto callback = [](base::OnceClosure quit_closure,
                     const SignEnterpriseChallengeReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_challenge_response());
    std::move(quit_closure).Run();
  };
  SignEnterpriseChallengeRequest request;
  request.set_va_type(va_type_);
  request.set_username("user");
  request.set_key_label("label");
  request.set_domain(key_info.domain());
  request.set_device_id(key_info.device_id());
  request.set_include_signed_public_key(false);
  request.set_challenge(CreateSignedChallenge("EnterpriseKeyChallenge"));
  service_->SignEnterpriseChallenge(request,
                                    base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceEnterpriseTest, SignEnterpriseChallengeBadPrefix) {
  KeyInfo key_info = CreateChallengeKeyInfo();
  std::string key_info_str;
  key_info.SerializeToString(&key_info_str);
  EXPECT_CALL(mock_crypto_utility_, VerifySignatureUsingHexKey(_, _, _, _))
      .WillRepeatedly(Return(true));
  auto callback = [](base::OnceClosure quit_closure,
                     const SignEnterpriseChallengeReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_challenge_response());
    std::move(quit_closure).Run();
  };
  SignEnterpriseChallengeRequest request;
  request.set_va_type(va_type_);
  request.set_username("user");
  request.set_key_label("label");
  request.set_domain(key_info.domain());
  request.set_device_id(key_info.device_id());
  request.set_include_signed_public_key(false);
  request.set_challenge(CreateSignedChallenge("bad_prefix"));
  service_->SignEnterpriseChallenge(request,
                                    base::BindOnce(callback, QuitClosure()));
  Run();
}

// Test that if |key_name_for_spkac| is not empty then the key associated to it
// is used for SignedPublicKeyAndChallenge.
TEST_P(AttestationServiceEnterpriseTest,
       SignEnterpriseChallengeUseKeyForSPKAC) {
  static const char kKeyNameForSpkac[] = "attest-ent-machine_temp_id";
  static const char kKeyNameForSpkacPublicKey[] =
      "attest-ent-machine_public_key";

  CertifiedKey& key = *mock_database_.GetMutableProtobuf()->add_device_keys();
  key.set_public_key("public_key");
  key.set_key_name("label");

  // Create a machine key for SPKAC
  CertifiedKey& key_for_spkac =
      *mock_database_.GetMutableProtobuf()->add_device_keys();
  key_for_spkac.set_key_blob("key_blob");
  key_for_spkac.set_public_key(kKeyNameForSpkacPublicKey);
  key_for_spkac.set_key_name(kKeyNameForSpkac);
  key_for_spkac.set_certified_key_credential("fake_cert_data");

  KeyInfo expected_key_info =
      CreateMachineChallengeKeyInfoWithSPKAC("fake_cert_data", "fake_spkac");
  std::string expected_key_info_str;
  expected_key_info.SerializeToString(&expected_key_info_str);

  ExpectGetCustomerId("customer_id");
  EXPECT_CALL(
      mock_crypto_utility_,
      VerifySignatureUsingHexKey(
          _, google_keys_.va_signing_key(va_type_).modulus_in_hex(), _, _))
      .WillOnce(Return(true));
  EXPECT_CALL(
      mock_crypto_utility_,
      EncryptDataForGoogle(
          expected_key_info_str,
          google_keys_.va_encryption_key(va_type_).modulus_in_hex(), _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(MockEncryptedData(expected_key_info_str)),
                Return(true)));

  // Expect |CreateSPKAC| to be called for |key_name_for_spkac|.
  EXPECT_CALL(
      mock_crypto_utility_,
      CreateSPKAC(key_for_spkac.key_blob(), key_for_spkac.public_key(), _, _))
      .WillOnce(
          DoAll(SetArgPointee<3>(std::string("fake_spkac")), Return(true)));

  EXPECT_CALL(mock_tpm_utility_, Sign(_, _, _))
      .WillOnce(
          DoAll(SetArgPointee<2>(std::string("signature")), Return(true)));

  auto callback = [](const std::string& expected_key_info_str,
                     base::OnceClosure quit_closure,
                     const SignEnterpriseChallengeReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_challenge_response());
    SignedData signed_data;
    EXPECT_TRUE(signed_data.ParseFromString(reply.challenge_response()));
    EXPECT_EQ("signature", signed_data.signature());
    ChallengeResponse response_pb;
    EXPECT_TRUE(response_pb.ParseFromString(signed_data.data()));
    // This relies on the fact that the mock for EncryptDataForGoogle just
    // passes the data unencrypted.
    EXPECT_EQ(expected_key_info_str,
              response_pb.encrypted_key_info().encrypted_data());
    std::move(quit_closure).Run();
  };
  SignEnterpriseChallengeRequest request;
  request.set_va_type(va_type_);
  request.set_key_label("label");
  request.set_domain("to_be_ignored");
  request.set_device_id(expected_key_info.device_id());
  request.set_include_signed_public_key(true);
  request.set_key_name_for_spkac(kKeyNameForSpkac);
  request.set_challenge(CreateSignedChallenge("EnterpriseKeyChallenge"));
  request.set_include_customer_id(true);
  service_->SignEnterpriseChallenge(
      request, base::BindOnce(callback, expected_key_info_str, QuitClosure()));
  Run();
}

INSTANTIATE_TEST_SUITE_P(VerifiedAccessType,
                         AttestationServiceEnterpriseTest,
                         ::testing::Values(DEFAULT_VA, TEST_VA));

class AttestationServiceCustomerIdTest : public AttestationServiceBaseTest {
 public:
  ~AttestationServiceCustomerIdTest() override = default;

  KeyInfo SetUpKeyInfoForCustomerId(bool include_customer_id,
                                    std::string customer_id) {
    if (include_customer_id) {
      ExpectGetCustomerId(customer_id);
    }

    GoogleKeys google_keys_;
    EXPECT_CALL(
        mock_crypto_utility_,
        VerifySignatureUsingHexKey(
            _, google_keys_.va_signing_key(DEFAULT_VA).modulus_in_hex(), _, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(mock_tpm_utility_, Sign(_, _, _))
        .WillRepeatedly(
            DoAll(SetArgPointee<2>(std::string("signature")), Return(true)));

    KeyInfo key_info = CreateChallengeKeyInfo(customer_id);
    std::string key_info_str;
    key_info.SerializeToString(&key_info_str);
    EXPECT_CALL(
        mock_crypto_utility_,
        EncryptDataForGoogle(
            key_info_str,
            google_keys_.va_encryption_key(DEFAULT_VA).modulus_in_hex(), _, _))
        .WillRepeatedly(DoAll(SetArgPointee<3>(MockEncryptedData(key_info_str)),
                              Return(true)));
    return key_info;
  }

 protected:
  auto CreateSuccessfulChallengeCallback(std::string customer_id) {
    auto callback = [](std::string customer_id, base::OnceClosure quit_closure,
                       const SignEnterpriseChallengeReply& reply) {
      EXPECT_EQ(STATUS_SUCCESS, reply.status());
      EXPECT_TRUE(reply.has_challenge_response());
      SignedData signed_data;
      EXPECT_TRUE(signed_data.ParseFromString(reply.challenge_response()));
      EXPECT_EQ("signature", signed_data.signature());
      ChallengeResponse response_pb;
      EXPECT_TRUE(response_pb.ParseFromString(signed_data.data()));
      EXPECT_EQ(CreateChallenge("EnterpriseKeyChallenge"),
                response_pb.challenge().data());
      KeyInfo key_info = CreateChallengeKeyInfo(customer_id);
      std::string key_info_str;
      key_info.SerializeToString(&key_info_str);
      EXPECT_EQ(key_info_str,
                response_pb.encrypted_key_info().encrypted_data());
      std::move(quit_closure).Run();
    };
    return base::BindOnce(callback, customer_id, QuitClosure());
  }

  SignEnterpriseChallengeRequest CreateChallengeRequest(
      const KeyInfo& key_info, bool include_customer_id) {
    SignEnterpriseChallengeRequest request;
    request.set_va_type(DEFAULT_VA);
    request.set_username("user");
    request.set_key_label("label");
    request.set_domain(key_info.domain());
    request.set_device_id(key_info.device_id());
    request.set_include_signed_public_key(false);
    request.set_challenge(CreateSignedChallenge("EnterpriseKeyChallenge"));
    request.set_include_customer_id(include_customer_id);
    return request;
  }
};

TEST_F(AttestationServiceCustomerIdTest, DoNotIncludeCustomerIdSucceeds) {
  bool include_customer_id = false;
  std::string customer_id = "";
  KeyInfo key_info =
      SetUpKeyInfoForCustomerId(include_customer_id, customer_id);
  SignEnterpriseChallengeRequest request =
      CreateChallengeRequest(key_info, include_customer_id);
  auto callback = CreateSuccessfulChallengeCallback(customer_id);
  service_->SignEnterpriseChallenge(request, std::move(callback));
  Run();
}

TEST_F(AttestationServiceCustomerIdTest, IncludeCustomerIdSucceeds) {
  bool include_customer_id = true;
  std::string customer_id = "customer_id";
  KeyInfo key_info =
      SetUpKeyInfoForCustomerId(include_customer_id, customer_id);
  SignEnterpriseChallengeRequest request =
      CreateChallengeRequest(key_info, include_customer_id);
  auto callback = CreateSuccessfulChallengeCallback(customer_id);
  service_->SignEnterpriseChallenge(request, std::move(callback));
  Run();
}

TEST_F(AttestationServiceCustomerIdTest,
       IncludeCustomerIdFailsWithoutActualCustomerId) {
  bool include_customer_id = true;
  KeyInfo key_info =
      SetUpKeyInfoForCustomerId(include_customer_id, /*customer_id=*/"");
  SignEnterpriseChallengeRequest request =
      CreateChallengeRequest(key_info, include_customer_id);
  auto callback = [](base::OnceClosure quit_closure,
                     const SignEnterpriseChallengeReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_challenge_response());
    std::move(quit_closure).Run();
  };
  service_->SignEnterpriseChallenge(request,
                                    base::BindOnce(callback, QuitClosure()));
  Run();
}

class AttestationServiceTest : public AttestationServiceBaseTest,
                               public testing::WithParamInterface<ACAType> {
 public:
  AttestationServiceTest() : aca_type_(GetParam()) {}
  ~AttestationServiceTest() override = default;

  void SetUp() override { AttestationServiceBaseTest::SetUp(); }

 protected:
  std::string CreateCAEnrollResponse(bool success) {
    AttestationEnrollmentResponse response_pb;
    if (success) {
      response_pb.set_status(OK);
      response_pb.set_detail("");
      response_pb.mutable_encrypted_identity_credential()->set_tpm_version(
          GetTpmVersionUnderTest());
      response_pb.mutable_encrypted_identity_credential()->set_asym_ca_contents(
          "1234");
      response_pb.mutable_encrypted_identity_credential()
          ->set_sym_ca_attestation("5678");
      response_pb.mutable_encrypted_identity_credential()->set_encrypted_seed(
          "seed");
      response_pb.mutable_encrypted_identity_credential()->set_credential_mac(
          "mac");
      response_pb.mutable_encrypted_identity_credential()
          ->mutable_wrapped_certificate()
          ->set_wrapped_key("wrapped");
    } else {
      response_pb.set_status(SERVER_ERROR);
      response_pb.set_detail("fake_enroll_error");
    }
    std::string response_str;
    response_pb.SerializeToString(&response_str);
    return response_str;
  }

  std::string CreateCACertResponse(bool success, std::string message_id) {
    AttestationCertificateResponse response_pb;
    if (success) {
      response_pb.set_status(OK);
      response_pb.set_detail("");
      response_pb.set_message_id(message_id);
      response_pb.set_certified_key_credential(kFakeCert);
      response_pb.set_intermediate_ca_cert(kFakeCaCert);
      *response_pb.add_additional_intermediate_ca_cert() = kFakeCaCert2;
    } else {
      response_pb.set_status(SERVER_ERROR);
      response_pb.set_message_id(message_id);
      response_pb.set_detail("fake_sign_error");
    }
    std::string response_str;
    response_pb.SerializeToString(&response_str);
    return response_str;
  }

  AttestationCertificateRequest GenerateCACertRequest() {
    SetUpIdentity(identity_);
    SetUpIdentityCertificate(identity_, DEFAULT_ACA);
    base::RunLoop loop;
    auto callback = [](base::RunLoop* loop,
                       AttestationCertificateRequest* pca_request,
                       const CreateCertificateRequestReply& reply) {
      pca_request->ParseFromString(reply.pca_request());
      loop->Quit();
    };
    CreateCertificateRequestRequest request;
    request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
    AttestationCertificateRequest pca_request;
    service_->CreateCertificateRequest(
        request, base::BindOnce(callback, &loop, &pca_request));
    loop.Run();
    return pca_request;
  }

  ACAType aca_type_;
};

TEST_P(AttestationServiceTest, GetAttestationKeyInfoSuccess) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  // Set expectations on the outputs.
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const GetAttestationKeyInfoReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ("public_key", reply.public_key());
    EXPECT_EQ("public_key_tpm", reply.public_key_tpm_format());
    EXPECT_EQ(cert_name, reply.certificate());
    EXPECT_EQ("pcr0", reply.pcr0_quote().quote());
    EXPECT_EQ("pcr1", reply.pcr1_quote().quote());
    std::move(quit_closure).Run();
  };
  GetAttestationKeyInfoRequest request;
  request.set_aca_type(aca_type_);
  service_->GetAttestationKeyInfo(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetAttestationKeyInfoNoInfo) {
  SetUpIdentityCertificate(identity_, aca_type_);
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const GetAttestationKeyInfoReply& reply) {
    EXPECT_EQ(STATUS_NOT_AVAILABLE, reply.status());
    EXPECT_FALSE(reply.has_public_key());
    EXPECT_FALSE(reply.has_public_key_tpm_format());
    EXPECT_FALSE(reply.has_certificate());
    EXPECT_FALSE(reply.has_pcr0_quote());
    EXPECT_FALSE(reply.has_pcr1_quote());
    std::move(quit_closure).Run();
  };
  GetAttestationKeyInfoRequest request;
  request.set_aca_type(aca_type_);
  service_->GetAttestationKeyInfo(request,
                                  base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetAttestationKeyInfoSomeInfo) {
  SetUpIdentity(identity_);
  auto* identity_data =
      mock_database_.GetMutableProtobuf()->mutable_identities()->Mutable(
          identity_);
  identity_data->mutable_identity_key()->clear_identity_public_key_der();
  identity_data->mutable_identity_binding()
      ->clear_identity_public_key_tpm_format();
  identity_data->mutable_pcr_quotes()->erase(0);
  SetUpIdentityCertificate(identity_, aca_type_);
  // Set expectations on the outputs.
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const GetAttestationKeyInfoReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_public_key());
    EXPECT_FALSE(reply.has_public_key_tpm_format());
    EXPECT_EQ(cert_name, reply.certificate());
    EXPECT_FALSE(reply.has_pcr0_quote());
    EXPECT_EQ("pcr1", reply.pcr1_quote().quote());
    std::move(quit_closure).Run();
  };
  GetAttestationKeyInfoRequest request;
  request.set_aca_type(aca_type_);
  service_->GetAttestationKeyInfo(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, ActivateAttestationKeySuccess) {
  SetUpIdentity(identity_);
  EXPECT_CALL(mock_database_, SaveChanges()).Times(1);
  const std::string cert_name = GetCertificateName(identity_, aca_type_);
  if (GetTpmVersionUnderTest() == TPM_1_2) {
    EXPECT_CALL(mock_tpm_utility_,
                ActivateIdentity(_, "encrypted1", "encrypted2", _))
        .WillOnce(DoAll(SetArgPointee<3>(cert_name), Return(true)));
  } else {
    EXPECT_CALL(
        mock_tpm_utility_,
        ActivateIdentityForTpm2(KEY_TYPE_ECC, _, "seed", "mac", "wrapped", _))
        .WillOnce(DoAll(SetArgPointee<5>(cert_name), Return(true)));
  }
  // Set expectations on the outputs.
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const ActivateAttestationKeyReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(cert_name, reply.certificate());
    std::move(quit_closure).Run();
  };
  ActivateAttestationKeyRequest request;
  request.set_aca_type(aca_type_);
  request.mutable_encrypted_certificate()->set_tpm_version(
      GetTpmVersionUnderTest());
  request.mutable_encrypted_certificate()->set_asym_ca_contents("encrypted1");
  request.mutable_encrypted_certificate()->set_sym_ca_attestation("encrypted2");
  request.mutable_encrypted_certificate()->set_encrypted_seed("seed");
  request.mutable_encrypted_certificate()->set_credential_mac("mac");
  request.mutable_encrypted_certificate()
      ->mutable_wrapped_certificate()
      ->set_wrapped_key("wrapped");
  request.set_save_certificate(true);
  service_->ActivateAttestationKey(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, ActivateAttestationKeySuccessNoSave) {
  SetUpIdentity(identity_);
  EXPECT_CALL(mock_database_, GetMutableProtobuf()).Times(0);
  EXPECT_CALL(mock_database_, SaveChanges()).Times(0);
  const std::string cert_name = GetCertificateName(identity_, aca_type_);
  if (GetTpmVersionUnderTest() == TPM_1_2) {
    EXPECT_CALL(mock_tpm_utility_,
                ActivateIdentity(_, "encrypted1", "encrypted2", _))
        .WillOnce(DoAll(SetArgPointee<3>(cert_name), Return(true)));
  } else {
    EXPECT_CALL(
        mock_tpm_utility_,
        ActivateIdentityForTpm2(KEY_TYPE_ECC, _, "seed", "mac", "wrapped", _))
        .WillOnce(DoAll(SetArgPointee<5>(cert_name), Return(true)));
  }
  // Set expectations on the outputs.
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const ActivateAttestationKeyReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(cert_name, reply.certificate());
    std::move(quit_closure).Run();
  };
  ActivateAttestationKeyRequest request;
  request.set_aca_type(aca_type_);
  request.mutable_encrypted_certificate()->set_tpm_version(
      GetTpmVersionUnderTest());
  request.mutable_encrypted_certificate()->set_asym_ca_contents("encrypted1");
  request.mutable_encrypted_certificate()->set_sym_ca_attestation("encrypted2");
  request.mutable_encrypted_certificate()->set_encrypted_seed("seed");
  request.mutable_encrypted_certificate()->set_credential_mac("mac");
  request.mutable_encrypted_certificate()
      ->mutable_wrapped_certificate()
      ->set_wrapped_key("wrapped");
  service_->ActivateAttestationKey(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, ActivateAttestationKeySaveFailure) {
  SetUpIdentity(identity_);
  EXPECT_CALL(mock_database_, SaveChanges()).WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const ActivateAttestationKeyReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  ActivateAttestationKeyRequest request;
  request.set_aca_type(aca_type_);
  request.mutable_encrypted_certificate()->set_tpm_version(
      GetTpmVersionUnderTest());
  request.mutable_encrypted_certificate()->set_asym_ca_contents("encrypted1");
  request.mutable_encrypted_certificate()->set_sym_ca_attestation("encrypted2");
  request.mutable_encrypted_certificate()->set_encrypted_seed("seed");
  request.mutable_encrypted_certificate()->set_credential_mac("mac");
  request.mutable_encrypted_certificate()
      ->mutable_wrapped_certificate()
      ->set_wrapped_key("wrapped");
  request.set_save_certificate(true);
  service_->ActivateAttestationKey(request,
                                   base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, ActivateAttestationKeyActivateFailure) {
  SetUpIdentity(identity_);
  if (GetTpmVersionUnderTest() == TPM_1_2) {
    EXPECT_CALL(mock_tpm_utility_,
                ActivateIdentity(_, "encrypted1", "encrypted2", _))
        .WillRepeatedly(Return(false));
  } else {
    EXPECT_CALL(
        mock_tpm_utility_,
        ActivateIdentityForTpm2(KEY_TYPE_ECC, _, "seed", "mac", "wrapped", _))
        .WillRepeatedly(Return(false));
  }
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const ActivateAttestationKeyReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  ActivateAttestationKeyRequest request;
  request.set_aca_type(aca_type_);
  request.mutable_encrypted_certificate()->set_tpm_version(
      GetTpmVersionUnderTest());
  request.mutable_encrypted_certificate()->set_asym_ca_contents("encrypted1");
  request.mutable_encrypted_certificate()->set_sym_ca_attestation("encrypted2");
  request.mutable_encrypted_certificate()->set_encrypted_seed("seed");
  request.mutable_encrypted_certificate()->set_credential_mac("mac");
  request.mutable_encrypted_certificate()
      ->mutable_wrapped_certificate()
      ->set_wrapped_key("wrapped");
  request.set_save_certificate(true);
  service_->ActivateAttestationKey(request,
                                   base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateCertifiableKeySuccess) {
  // We need an identity to create a certifiable key.
  SetUpIdentity(identity_);

  // Configure a fake TPM response.
  EXPECT_CALL(mock_tpm_utility_,
              CreateCertifiedKey(KEY_TYPE_RSA, KEY_USAGE_SIGN,
                                 KeyRestriction::kUnrestricted,
                                 Eq(std::nullopt), _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(std::string("public_key")),
                      SetArgPointee<9>(std::string("certify_info")),
                      SetArgPointee<10>(std::string("certify_info_signature")),
                      Return(true)));
  // Expect the key to be written exactly once.
  EXPECT_CALL(mock_key_store_, Write("user", "label", _)).Times(1);
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateCertifiableKeyReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ("public_key", reply.public_key());
    EXPECT_EQ("certify_info", reply.certify_info());
    EXPECT_EQ("certify_info_signature", reply.certify_info_signature());
    std::move(quit_closure).Run();
  };
  CreateCertifiableKeyRequest request;
  request.set_key_label("label");
  request.set_key_type(KEY_TYPE_RSA);
  request.set_key_usage(KEY_USAGE_SIGN);
  request.set_username("user");
  service_->CreateCertifiableKey(request,
                                 base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateCertifiableKeySuccessNoUser) {
  // We need an identity to create a certifiable key.
  SetUpIdentity(identity_);

  // Configure a fake TPM response.
  EXPECT_CALL(mock_tpm_utility_,
              CreateCertifiedKey(KEY_TYPE_RSA, KEY_USAGE_SIGN,
                                 KeyRestriction::kUnrestricted,
                                 Eq(std::nullopt), _, _, _, _, _, _, _))
      .WillOnce(DoAll(SetArgPointee<7>(std::string("public_key")),
                      SetArgPointee<9>(std::string("certify_info")),
                      SetArgPointee<10>(std::string("certify_info_signature")),
                      Return(true)));
  // Expect the key to be written exactly once.
  EXPECT_CALL(mock_database_, SaveChanges()).Times(1);
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateCertifiableKeyReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ("public_key", reply.public_key());
    EXPECT_EQ("certify_info", reply.certify_info());
    EXPECT_EQ("certify_info_signature", reply.certify_info_signature());
    std::move(quit_closure).Run();
  };
  CreateCertifiableKeyRequest request;
  request.set_key_label("label");
  request.set_key_type(KEY_TYPE_RSA);
  request.set_key_usage(KEY_USAGE_SIGN);
  service_->CreateCertifiableKey(request,
                                 base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateCertifiableKeyRNGFailure) {
  // We need an identity to make sure it didn't fail because of that.
  SetUpIdentity(identity_);

  EXPECT_CALL(mock_crypto_utility_, GetRandom(_, _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateCertifiableKeyReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_public_key());
    EXPECT_FALSE(reply.has_certify_info());
    EXPECT_FALSE(reply.has_certify_info_signature());
    std::move(quit_closure).Run();
  };
  CreateCertifiableKeyRequest request;
  request.set_key_label("label");
  request.set_key_type(KEY_TYPE_RSA);
  request.set_key_usage(KEY_USAGE_SIGN);
  service_->CreateCertifiableKey(request,
                                 base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateCertifiableKeyNoIdentityFailure) {
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateCertifiableKeyReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_public_key());
    EXPECT_FALSE(reply.has_certify_info());
    EXPECT_FALSE(reply.has_certify_info_signature());
    std::move(quit_closure).Run();
  };
  CreateCertifiableKeyRequest request;
  request.set_key_label("label");
  request.set_key_type(KEY_TYPE_RSA);
  request.set_key_usage(KEY_USAGE_SIGN);
  service_->CreateCertifiableKey(request,
                                 base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateCertifiableKeyTpmCreateFailure) {
  // We need an identity to create a certifiable key.
  SetUpIdentity(identity_);

  EXPECT_CALL(mock_tpm_utility_,
              CreateCertifiedKey(_, _, _, _, _, _, _, _, _, _, _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateCertifiableKeyReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_public_key());
    EXPECT_FALSE(reply.has_certify_info());
    EXPECT_FALSE(reply.has_certify_info_signature());
    std::move(quit_closure).Run();
  };
  CreateCertifiableKeyRequest request;
  request.set_key_label("label");
  request.set_key_type(KEY_TYPE_RSA);
  request.set_key_usage(KEY_USAGE_SIGN);
  service_->CreateCertifiableKey(request,
                                 base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateCertifiableKeyDBFailure) {
  // We need an identity to make sure it didn't fail because of that.
  SetUpIdentity(identity_);

  EXPECT_CALL(mock_key_store_, Write(_, _, _)).WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateCertifiableKeyReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_public_key());
    EXPECT_FALSE(reply.has_certify_info());
    EXPECT_FALSE(reply.has_certify_info_signature());
    std::move(quit_closure).Run();
  };
  CreateCertifiableKeyRequest request;
  request.set_key_label("label");
  request.set_key_type(KEY_TYPE_RSA);
  request.set_key_usage(KEY_USAGE_SIGN);
  request.set_username("username");
  service_->CreateCertifiableKey(request,
                                 base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateCertifiableKeyDBFailureNoUser) {
  // We need an identity to make sure it didn't fail because of that.
  SetUpIdentity(identity_);

  EXPECT_CALL(mock_database_, SaveChanges()).WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateCertifiableKeyReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_public_key());
    EXPECT_FALSE(reply.has_certify_info());
    EXPECT_FALSE(reply.has_certify_info_signature());
    std::move(quit_closure).Run();
  };
  CreateCertifiableKeyRequest request;
  request.set_key_label("label");
  request.set_key_type(KEY_TYPE_RSA);
  request.set_key_usage(KEY_USAGE_SIGN);
  service_->CreateCertifiableKey(request,
                                 base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DecryptSuccess) {
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const DecryptReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(MockTpmUtility::Transform("Unbind", "data"),
              reply.decrypted_data());
    std::move(quit_closure).Run();
  };
  DecryptRequest request;
  request.set_key_label("label");
  request.set_username("user");
  request.set_encrypted_data("data");
  service_->Decrypt(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DecryptSuccessNoUser) {
  mock_database_.GetMutableProtobuf()->add_device_keys()->set_key_name("label");
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const DecryptReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(MockTpmUtility::Transform("Unbind", "data"),
              reply.decrypted_data());
    std::move(quit_closure).Run();
  };
  DecryptRequest request;
  request.set_key_label("label");
  request.set_encrypted_data("data");
  service_->Decrypt(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DecryptKeyNotFound) {
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const DecryptReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_decrypted_data());
    std::move(quit_closure).Run();
  };
  DecryptRequest request;
  request.set_key_label("label");
  request.set_username("user");
  request.set_encrypted_data("data");
  service_->Decrypt(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DecryptKeyNotFoundNoUser) {
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const DecryptReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_decrypted_data());
    std::move(quit_closure).Run();
  };
  DecryptRequest request;
  request.set_key_label("label");
  request.set_encrypted_data("data");
  service_->Decrypt(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DecryptUnbindFailure) {
  EXPECT_CALL(mock_tpm_utility_, Unbind(_, _, _)).WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const DecryptReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_decrypted_data());
    std::move(quit_closure).Run();
  };
  DecryptRequest request;
  request.set_key_label("label");
  request.set_username("user");
  request.set_encrypted_data("data");
  service_->Decrypt(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, SignSuccess) {
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure, const SignReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(MockTpmUtility::Transform("Sign", "data"), reply.signature());
    std::move(quit_closure).Run();
  };
  SignRequest request;
  request.set_key_label("label");
  request.set_username("user");
  request.set_data_to_sign("data");
  service_->Sign(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, SignSuccessNoUser) {
  mock_database_.GetMutableProtobuf()->add_device_keys()->set_key_name("label");
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure, const SignReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(MockTpmUtility::Transform("Sign", "data"), reply.signature());
    std::move(quit_closure).Run();
  };
  SignRequest request;
  request.set_key_label("label");
  request.set_data_to_sign("data");
  service_->Sign(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, SignKeyNotFound) {
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure, const SignReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_signature());
    std::move(quit_closure).Run();
  };
  SignRequest request;
  request.set_key_label("label");
  request.set_username("user");
  request.set_data_to_sign("data");
  service_->Sign(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, SignKeyNotFoundNoUser) {
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure, const SignReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_signature());
    std::move(quit_closure).Run();
  };
  SignRequest request;
  request.set_key_label("label");
  request.set_data_to_sign("data");
  service_->Sign(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, SignUnbindFailure) {
  EXPECT_CALL(mock_tpm_utility_, Sign(_, _, _)).WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure, const SignReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_signature());
    std::move(quit_closure).Run();
  };
  SignRequest request;
  request.set_key_label("label");
  request.set_username("user");
  request.set_data_to_sign("data");
  service_->Sign(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, RegisterSuccess) {
  // Setup a key in the user key store.
  CertifiedKey key;
  key.set_key_blob("key_blob");
  key.set_public_key("public_key");
  key.set_certified_key_credential(kFakeCert);
  key.set_intermediate_ca_cert(kFakeCaCert);
  *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
  key.set_key_name("label");
  key.set_key_type(KEY_TYPE_RSA);
  key.set_key_usage(KEY_USAGE_SIGN);
  std::string key_bytes;
  key.SerializeToString(&key_bytes);
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(DoAll(SetArgPointee<2>(key_bytes), Return(true)));
  // Cardinality is verified here to verify various steps are performed and to
  // catch performance regressions.
  EXPECT_CALL(mock_key_store_,
              Register("user", "label", KEY_TYPE_RSA, KEY_USAGE_SIGN,
                       "key_blob", "public_key", ""))
      .Times(1);
  EXPECT_CALL(mock_key_store_, RegisterCertificate(_, _)).Times(0);
  EXPECT_CALL(mock_key_store_, Delete("user", "label")).Times(1);
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const RegisterKeyWithChapsTokenReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  RegisterKeyWithChapsTokenRequest request;
  request.set_key_label("label");
  request.set_username("user");
  service_->RegisterKeyWithChapsToken(request,
                                      base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, RegisterSuccessNoUser) {
  // Setup a key in the device_keys field.
  CertifiedKey& key = *mock_database_.GetMutableProtobuf()->add_device_keys();
  key.set_key_blob("key_blob");
  key.set_public_key("public_key");
  key.set_certified_key_credential(kFakeCert);
  key.set_intermediate_ca_cert(kFakeCaCert);
  *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
  key.set_key_name("label");
  key.set_key_type(KEY_TYPE_RSA);
  key.set_key_usage(KEY_USAGE_SIGN);
  // Cardinality is verified here to verify various steps are performed and to
  // catch performance regressions.
  EXPECT_CALL(mock_key_store_,
              Register("", "label", KEY_TYPE_RSA, KEY_USAGE_SIGN, "key_blob",
                       "public_key", ""))
      .Times(1);
  EXPECT_CALL(mock_key_store_, RegisterCertificate(_, _)).Times(0);
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure, Database* database,
                     const RegisterKeyWithChapsTokenReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(0, database->GetMutableProtobuf()->device_keys_size());
    std::move(quit_closure).Run();
  };
  RegisterKeyWithChapsTokenRequest request;
  request.set_key_label("label");
  service_->RegisterKeyWithChapsToken(
      request, base::BindOnce(callback, QuitClosure(), &mock_database_));
  Run();
}

TEST_P(AttestationServiceTest, RegisterSuccessWithCertificates) {
  // Setup a key in the user key store.
  CertifiedKey key;
  key.set_key_blob("key_blob");
  key.set_public_key("public_key");
  key.set_certified_key_credential(kFakeCert);
  key.set_intermediate_ca_cert(kFakeCaCert);
  *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
  key.set_key_name("label");
  key.set_key_type(KEY_TYPE_RSA);
  key.set_key_usage(KEY_USAGE_SIGN);
  std::string key_bytes;
  key.SerializeToString(&key_bytes);
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(DoAll(SetArgPointee<2>(key_bytes), Return(true)));
  // Cardinality is verified here to verify various steps are performed and to
  // catch performance regressions.
  EXPECT_CALL(mock_key_store_,
              Register("user", "label", KEY_TYPE_RSA, KEY_USAGE_SIGN,
                       "key_blob", "public_key", kFakeCert))
      .Times(1);
  EXPECT_CALL(mock_key_store_, RegisterCertificate("user", kFakeCaCert))
      .Times(1);
  EXPECT_CALL(mock_key_store_, RegisterCertificate("user", kFakeCaCert2))
      .Times(1);
  EXPECT_CALL(mock_key_store_, Delete("user", "label")).Times(1);
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const RegisterKeyWithChapsTokenReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  RegisterKeyWithChapsTokenRequest request;
  request.set_key_label("label");
  request.set_username("user");
  request.set_include_certificates(true);
  service_->RegisterKeyWithChapsToken(request,
                                      base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, RegisterSuccessNoUserWithCertificates) {
  // Setup a key in the device_keys field.
  CertifiedKey& key = *mock_database_.GetMutableProtobuf()->add_device_keys();
  key.set_key_blob("key_blob");
  key.set_public_key("public_key");
  key.set_certified_key_credential(kFakeCert);
  key.set_intermediate_ca_cert(kFakeCaCert);
  *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
  key.set_key_name("label");
  key.set_key_type(KEY_TYPE_RSA);
  key.set_key_usage(KEY_USAGE_SIGN);
  // Cardinality is verified here to verify various steps are performed and to
  // catch performance regressions.
  EXPECT_CALL(mock_key_store_,
              Register("", "label", KEY_TYPE_RSA, KEY_USAGE_SIGN, "key_blob",
                       "public_key", kFakeCert))
      .Times(1);
  EXPECT_CALL(mock_key_store_, RegisterCertificate("", kFakeCaCert)).Times(1);
  EXPECT_CALL(mock_key_store_, RegisterCertificate("", kFakeCaCert2)).Times(1);
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure, Database* database,
                     const RegisterKeyWithChapsTokenReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(0, database->GetMutableProtobuf()->device_keys_size());
    std::move(quit_closure).Run();
  };
  RegisterKeyWithChapsTokenRequest request;
  request.set_key_label("label");
  request.set_include_certificates(true);
  service_->RegisterKeyWithChapsToken(
      request, base::BindOnce(callback, QuitClosure(), &mock_database_));
  Run();
}

TEST_P(AttestationServiceTest, RegisterNoKey) {
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const RegisterKeyWithChapsTokenReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  RegisterKeyWithChapsTokenRequest request;
  request.set_key_label("label");
  request.set_username("user");
  service_->RegisterKeyWithChapsToken(request,
                                      base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, RegisterNoKeyNoUser) {
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const RegisterKeyWithChapsTokenReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  RegisterKeyWithChapsTokenRequest request;
  request.set_key_label("label");
  service_->RegisterKeyWithChapsToken(request,
                                      base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, RegisterFailure) {
  // Setup a key in the user key store.
  CertifiedKey key;
  key.set_key_name("label");
  std::string key_bytes;
  key.SerializeToString(&key_bytes);
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(DoAll(SetArgPointee<2>(key_bytes), Return(true)));
  EXPECT_CALL(mock_key_store_, Register(_, _, _, _, _, _, _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const RegisterKeyWithChapsTokenReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  RegisterKeyWithChapsTokenRequest request;
  request.set_key_label("label");
  request.set_username("user");
  service_->RegisterKeyWithChapsToken(request,
                                      base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, RegisterIntermediateFailure) {
  // Setup a key in the user key store.
  CertifiedKey key;
  key.set_key_name("label");
  key.set_intermediate_ca_cert(kFakeCaCert);
  std::string key_bytes;
  key.SerializeToString(&key_bytes);
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(DoAll(SetArgPointee<2>(key_bytes), Return(true)));
  EXPECT_CALL(mock_key_store_, RegisterCertificate(_, _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const RegisterKeyWithChapsTokenReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  RegisterKeyWithChapsTokenRequest request;
  request.set_key_label("label");
  request.set_username("user");
  request.set_include_certificates(true);
  service_->RegisterKeyWithChapsToken(request,
                                      base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, RegisterAdditionalFailure) {
  // Setup a key in the user key store.
  CertifiedKey key;
  key.set_key_name("label");
  *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
  std::string key_bytes;
  key.SerializeToString(&key_bytes);
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(DoAll(SetArgPointee<2>(key_bytes), Return(true)));
  EXPECT_CALL(mock_key_store_, RegisterCertificate(_, _))
      .WillRepeatedly(Return(false));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const RegisterKeyWithChapsTokenReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  RegisterKeyWithChapsTokenRequest request;
  request.set_key_label("label");
  request.set_username("user");
  request.set_include_certificates(true);
  service_->RegisterKeyWithChapsToken(request,
                                      base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DeleteKeysByLabelSuccess) {
  // Setup a key in the user key store.
  CertifiedKey key;
  key.set_key_blob("key_blob");
  key.set_public_key("public_key");
  key.set_certified_key_credential(kFakeCert);
  key.set_intermediate_ca_cert(kFakeCaCert);
  *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
  key.set_key_name("label");
  key.set_key_type(KEY_TYPE_RSA);
  key.set_key_usage(KEY_USAGE_SIGN);
  std::string key_bytes;
  key.SerializeToString(&key_bytes);

  EXPECT_CALL(mock_key_store_, Delete("user", "label"))
      .Times(1)
      .WillOnce(Return(true));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const DeleteKeysReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  DeleteKeysRequest request;
  request.set_key_label_match("label");
  request.set_match_behavior(DeleteKeysRequest::MATCH_BEHAVIOR_EXACT);
  request.set_username("user");
  service_->DeleteKeys(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DeleteKeyByLabelNoUserSuccess) {
  // Setup a key in the device_keys field.
  CertifiedKey& key = *mock_database_.GetMutableProtobuf()->add_device_keys();
  key.set_key_blob("key_blob");
  key.set_public_key("public_key");
  key.set_certified_key_credential(kFakeCert);
  key.set_intermediate_ca_cert(kFakeCaCert);
  *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
  key.set_key_name("label");
  key.set_key_type(KEY_TYPE_RSA);
  key.set_key_usage(KEY_USAGE_SIGN);

  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure, Database* database,
                     const DeleteKeysReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(0, database->GetMutableProtobuf()->device_keys_size());
    std::move(quit_closure).Run();
  };
  DeleteKeysRequest request;
  request.set_key_label_match("label");
  request.set_match_behavior(DeleteKeysRequest::MATCH_BEHAVIOR_EXACT);
  service_->DeleteKeys(
      request, base::BindOnce(callback, QuitClosure(), &mock_database_));
  Run();
}

TEST_P(AttestationServiceTest, DeleteKeysByLabelNoKey) {
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const DeleteKeysReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  DeleteKeysRequest request;
  request.set_key_label_match("label");
  request.set_match_behavior(DeleteKeysRequest::MATCH_BEHAVIOR_EXACT);
  request.set_username("user");
  service_->DeleteKeys(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DeleteKeyByLabelNoUserNoKey) {
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const DeleteKeysReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  DeleteKeysRequest request;
  request.set_key_label_match("label");
  request.set_match_behavior(DeleteKeysRequest::MATCH_BEHAVIOR_EXACT);
  service_->DeleteKeys(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DeleteKeysByPrefixSuccess) {
  EXPECT_CALL(mock_key_store_, DeleteByPrefix("user", "label"))
      .Times(1)
      .WillOnce(Return(true));
  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure,
                     const DeleteKeysReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  DeleteKeysRequest request;
  request.set_key_label_match("label");
  request.set_username("user");
  service_->DeleteKeys(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, DeleteKeyByPrefixNoUserSuccess) {
  // Setup a key in the device_keys field.
  const std::string key_labels[] = {"label1", "label2", "otherprefix"};
  for (const auto& key_label : key_labels) {
    CertifiedKey& key = *mock_database_.GetMutableProtobuf()->add_device_keys();
    key.set_key_blob("key_blob");
    key.set_public_key("public_key");
    key.set_certified_key_credential(kFakeCert);
    key.set_intermediate_ca_cert(kFakeCaCert);
    *key.add_additional_intermediate_ca_cert() = kFakeCaCert2;
    key.set_key_name(key_label);
    key.set_key_type(KEY_TYPE_RSA);
    key.set_key_usage(KEY_USAGE_SIGN);
  }

  // Set expectations on the outputs.
  auto callback = [](base::OnceClosure quit_closure, Database* database,
                     const DeleteKeysReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_EQ(1, database->GetMutableProtobuf()->device_keys_size());
    EXPECT_EQ("otherprefix",
              database->GetMutableProtobuf()->device_keys()[0].key_name());
    std::move(quit_closure).Run();
  };
  DeleteKeysRequest request;
  request.set_key_label_match("label");
  service_->DeleteKeys(
      request, base::BindOnce(callback, QuitClosure(), &mock_database_));
  Run();
}

TEST_P(AttestationServiceTest, PrepareForEnrollmentQuoteRsa) {
  // Start with an empty database.
  mock_database_.GetMutableProtobuf()->Clear();
  // Schedule initialization again to make sure it runs after this point.
  service_->set_default_endorsement_key_type(KEY_TYPE_ECC);
  service_->set_endorsement_key_for_enrollment_id(KEY_TYPE_RSA);
  EXPECT_CALL(mock_nvram_quoter_, GetListForIdentity())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({BOARD_ID, SN_BITS})));
  EXPECT_CALL(mock_nvram_quoter_, Certify(BOARD_ID, _, _));
  EXPECT_CALL(mock_nvram_quoter_, Certify(SN_BITS, _, _));
  EXPECT_CALL(mock_nvram_quoter_, Certify(RSA_PUB_EK_CERT, _, _));
  ASSERT_TRUE(
      CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                 base::Unretained(service_.get()))));
  // One identity has been created.
  EXPECT_EQ(1, mock_database_.GetProtobuf().identities().size());
  const AttestationDatabase::Identity& identity_data =
      mock_database_.GetProtobuf().identities().Get(0);
  EXPECT_TRUE(identity_data.has_identity_binding());
  EXPECT_TRUE(identity_data.has_identity_key());
  EXPECT_EQ(1, identity_data.pcr_quotes().count(0));
  EXPECT_EQ(1, identity_data.pcr_quotes().count(1));
  EXPECT_EQ(IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID,
            identity_data.features());
  EXPECT_EQ(1, identity_data.nvram_quotes().count(BOARD_ID));
  EXPECT_EQ(1, identity_data.nvram_quotes().count(SN_BITS));
  EXPECT_EQ(1, identity_data.nvram_quotes().count(RSA_PUB_EK_CERT));

  // Deprecated identity-related values have not been set.
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_key());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_binding());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr0_quote());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr1_quote());

  // Verify Privacy CA-related data.
  VerifyACAData(mock_database_.GetProtobuf());
  // These deprecated fields have not been set either.
  EXPECT_TRUE(mock_database_.GetProtobuf().has_credentials());
  EXPECT_FALSE(mock_database_.GetProtobuf()
                   .credentials()
                   .has_default_encrypted_endorsement_credential());
}

TEST_P(AttestationServiceTest, PrepareForEnrollmentQuoteRsaFail) {
  // Start with an empty database.
  mock_database_.GetMutableProtobuf()->Clear();
  // Schedule initialization again to make sure it runs after this point.
  service_->set_default_endorsement_key_type(KEY_TYPE_ECC);
  service_->set_endorsement_key_for_enrollment_id(KEY_TYPE_RSA);
  EXPECT_CALL(mock_nvram_quoter_, GetListForIdentity())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({BOARD_ID, SN_BITS})));
  EXPECT_CALL(mock_nvram_quoter_, Certify(BOARD_ID, _, _));
  EXPECT_CALL(mock_nvram_quoter_, Certify(SN_BITS, _, _));
  EXPECT_CALL(mock_nvram_quoter_, Certify(RSA_PUB_EK_CERT, _, _))
      .WillOnce(Return(false));
  CHECK(CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                   base::Unretained(service_.get()))));
  // One identity has been created.
  EXPECT_TRUE(mock_database_.GetProtobuf().identities().empty());
}

TEST_P(AttestationServiceTest, PrepareForEnrollmentNoQuoteRsaEccEk) {
  // Start with an empty database.
  mock_database_.GetMutableProtobuf()->Clear();
  // Schedule initialization again to make sure it runs after this point.
  service_->set_default_endorsement_key_type(KEY_TYPE_ECC);
  service_->set_endorsement_key_for_enrollment_id(KEY_TYPE_ECC);
  EXPECT_CALL(mock_nvram_quoter_, GetListForIdentity())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({BOARD_ID, SN_BITS})));
  EXPECT_CALL(mock_nvram_quoter_, Certify(BOARD_ID, _, _));
  EXPECT_CALL(mock_nvram_quoter_, Certify(SN_BITS, _, _));
  ASSERT_TRUE(
      CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                 base::Unretained(service_.get()))));
  // One identity has been created.
  EXPECT_EQ(1, mock_database_.GetProtobuf().identities().size());
  const AttestationDatabase::Identity& identity_data =
      mock_database_.GetProtobuf().identities().Get(0);
  EXPECT_TRUE(identity_data.has_identity_binding());
  EXPECT_TRUE(identity_data.has_identity_key());
  EXPECT_EQ(1, identity_data.pcr_quotes().count(0));
  EXPECT_EQ(1, identity_data.pcr_quotes().count(1));
  EXPECT_EQ(IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID,
            identity_data.features());
  EXPECT_EQ(1, identity_data.nvram_quotes().count(BOARD_ID));
  EXPECT_EQ(1, identity_data.nvram_quotes().count(SN_BITS));
  EXPECT_EQ(0, identity_data.nvram_quotes().count(RSA_PUB_EK_CERT));

  // Deprecated identity-related values have not been set.
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_key());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_binding());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr0_quote());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr1_quote());

  // Verify Privacy CA-related data.
  VerifyACAData(mock_database_.GetProtobuf());
  // These deprecated fields have not been set either.
  EXPECT_TRUE(mock_database_.GetProtobuf().has_credentials());
  EXPECT_FALSE(mock_database_.GetProtobuf()
                   .credentials()
                   .has_default_encrypted_endorsement_credential());
}

TEST_P(AttestationServiceTest, PrepareForEnrollmentNoQuoteRsaRsaEk) {
  // Start with an empty database.
  mock_database_.GetMutableProtobuf()->Clear();
  // Schedule initialization again to make sure it runs after this point.
  service_->set_default_endorsement_key_type(KEY_TYPE_RSA);
  service_->set_endorsement_key_for_enrollment_id(KEY_TYPE_RSA);
  EXPECT_CALL(mock_nvram_quoter_, GetListForIdentity())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({BOARD_ID, SN_BITS})));
  EXPECT_CALL(mock_nvram_quoter_, Certify(BOARD_ID, _, _));
  EXPECT_CALL(mock_nvram_quoter_, Certify(SN_BITS, _, _));
  ASSERT_TRUE(
      CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                 base::Unretained(service_.get()))));
  // One identity has been created.
  EXPECT_EQ(1, mock_database_.GetProtobuf().identities().size());
  const AttestationDatabase::Identity& identity_data =
      mock_database_.GetProtobuf().identities().Get(0);
  EXPECT_TRUE(identity_data.has_identity_binding());
  EXPECT_TRUE(identity_data.has_identity_key());
  EXPECT_EQ(1, identity_data.pcr_quotes().count(0));
  EXPECT_EQ(1, identity_data.pcr_quotes().count(1));
  EXPECT_EQ(IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID,
            identity_data.features());
  EXPECT_EQ(1, identity_data.nvram_quotes().count(BOARD_ID));
  EXPECT_EQ(1, identity_data.nvram_quotes().count(SN_BITS));
  EXPECT_EQ(0, identity_data.nvram_quotes().count(RSA_PUB_EK_CERT));

  // Deprecated identity-related values have not been set.
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_key());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_binding());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr0_quote());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr1_quote());

  // Verify Privacy CA-related data.
  VerifyACAData(mock_database_.GetProtobuf());
  // These deprecated fields have not been set either.
  EXPECT_TRUE(mock_database_.GetProtobuf().has_credentials());
  EXPECT_FALSE(mock_database_.GetProtobuf()
                   .credentials()
                   .has_default_encrypted_endorsement_credential());
}

TEST_P(AttestationServiceTest,
       PrepareForEnrollmentQuoteForIdentityContinueOnFail) {
  // Start with an empty database.
  mock_database_.GetMutableProtobuf()->Clear();
  // Schedule initialization again to make sure it runs after this point.
  service_->set_default_endorsement_key_type(KEY_TYPE_ECC);
  service_->set_endorsement_key_for_enrollment_id(KEY_TYPE_ECC);
  EXPECT_CALL(mock_nvram_quoter_, GetListForIdentity())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({BOARD_ID, SN_BITS})));
  EXPECT_CALL(mock_nvram_quoter_, Certify(BOARD_ID, _, _))
      .WillOnce(Return(false));
  EXPECT_CALL(mock_nvram_quoter_, Certify(SN_BITS, _, _))
      .WillOnce(Return(false));

  ASSERT_TRUE(
      CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                 base::Unretained(service_.get()))));
  // One identity has been created.
  EXPECT_EQ(1, mock_database_.GetProtobuf().identities().size());
  const AttestationDatabase::Identity& identity_data =
      mock_database_.GetProtobuf().identities().Get(0);
  EXPECT_TRUE(identity_data.has_identity_binding());
  EXPECT_TRUE(identity_data.has_identity_key());
  EXPECT_EQ(1, identity_data.pcr_quotes().count(0));
  EXPECT_EQ(1, identity_data.pcr_quotes().count(1));
  EXPECT_EQ(IDENTITY_FEATURE_ENTERPRISE_ENROLLMENT_ID,
            identity_data.features());
  EXPECT_TRUE(identity_data.nvram_quotes().empty());

  // Deprecated identity-related values have not been set.
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_key());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_binding());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr0_quote());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr1_quote());

  // Verify Privacy CA-related data.
  VerifyACAData(mock_database_.GetProtobuf());
  // These deprecated fields have not been set either.
  EXPECT_TRUE(mock_database_.GetProtobuf().has_credentials());
  EXPECT_FALSE(mock_database_.GetProtobuf()
                   .credentials()
                   .has_default_encrypted_endorsement_credential());
}

TEST_P(AttestationServiceTest, PrepareForEnrollmentNoPublicKey) {
  // Start with an empty database.
  mock_database_.GetMutableProtobuf()->Clear();
  EXPECT_CALL(mock_tpm_utility_, GetEndorsementPublicKey(_, _))
      .WillRepeatedly(Return(false));
  // Schedule initialization again to make sure it runs after this point.
  CHECK(CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                   base::Unretained(service_.get()))));
  EXPECT_FALSE(mock_database_.GetProtobuf().has_credentials());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_key());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_binding());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr0_quote());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr1_quote());
}

TEST_P(AttestationServiceTest, PrepareForEnrollmentNoCert) {
  // Start with an empty database.
  mock_database_.GetMutableProtobuf()->Clear();
  EXPECT_CALL(mock_tpm_utility_, GetEndorsementCertificate(_, _))
      .WillRepeatedly(Return(false));
  // Schedule initialization again to make sure it runs after this point.
  CHECK(CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                   base::Unretained(service_.get()))));
  EXPECT_FALSE(mock_database_.GetProtobuf().has_credentials());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_key());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_binding());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr0_quote());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr1_quote());
}

TEST_P(AttestationServiceTest, PrepareForEnrollmentFailAIK) {
  // Start with an empty database.
  mock_database_.GetMutableProtobuf()->Clear();
  EXPECT_CALL(mock_tpm_utility_, CreateIdentity(_, _))
      .WillRepeatedly(Return(false));
  // Schedule initialization again to make sure it runs after this point.
  CHECK(CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                   base::Unretained(service_.get()))));
  // No identity was created.
  EXPECT_EQ(0, mock_database_.GetProtobuf().identities().size());
  // And no credentials were stored.
  EXPECT_FALSE(mock_database_.GetProtobuf().has_credentials());
}

TEST_P(AttestationServiceTest, PrepareForEnrollmentFailQuote) {
  // Start with an empty database.
  mock_database_.GetMutableProtobuf()->Clear();
  EXPECT_CALL(mock_hwsec_, Quote)
      .WillRepeatedly(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  // Schedule initialization again to make sure it runs after this point.
  CHECK(CallAndWait(base::BindOnce(&AttestationService::InitializeWithCallback,
                                   base::Unretained(service_.get()))));
  EXPECT_FALSE(mock_database_.GetProtobuf().has_credentials());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_key());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_identity_binding());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr0_quote());
  EXPECT_FALSE(mock_database_.GetProtobuf().has_pcr1_quote());
}

TEST_P(AttestationServiceTest, ComputeEnterpriseEnrollmentId) {
  EXPECT_CALL(mock_tpm_utility_, GetEndorsementPublicKeyBytes(_, _))
      .WillRepeatedly(
          DoAll(SetArgPointee<1>(std::string("ekm")), Return(true)));
  brillo::SecureBlob abe_data(0xCA, 32);
  service_->set_abe_data(&abe_data);
  CryptoUtilityImpl crypto_utility(&mock_tpm_utility_, &mock_hwsec_);
  service_->set_crypto_utility(&crypto_utility);
  std::string enrollment_id = ComputeEnterpriseEnrollmentId();
  EXPECT_EQ("635c4526dfa583362273e2987944007b09131cfa0f4e5874e7a76d55d333e3cc",
            base::ToLowerASCII(
                base::HexEncode(enrollment_id.data(), enrollment_id.size())));
}

TEST_P(AttestationServiceTest, CreateCertificateRequestSuccess) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_pca_request());
    AttestationCertificateRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));
    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_EQ(ENTERPRISE_MACHINE_CERTIFICATE, pca_request.profile());
    EXPECT_TRUE(pca_request.nvram_quotes().empty());
    EXPECT_EQ(cert_name, pca_request.identity_credential());
    std::move(quit_closure).Run();
  };
  CreateCertificateRequestRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateDeviceTrustUserCertificateRequestSuccess) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);

  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());

    EXPECT_TRUE(reply.has_pca_request());
    AttestationCertificateRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));

    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_TRUE(pca_request.nvram_quotes().empty());

    EXPECT_EQ(cert_name, pca_request.identity_credential());
    EXPECT_EQ(ENTERPRISE_USER_CERTIFICATE, pca_request.profile());
    EXPECT_FALSE(pca_request.has_origin());
    std::move(quit_closure).Run();
  };

  CreateCertificateRequestRequest request;
  request.set_certificate_profile(DEVICE_TRUST_USER_CERTIFICATE);
  request.set_aca_type(aca_type_);
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateDeviceSetupCertificateRequestSuccess) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);

  auto callback = [](const std::string& id, const std::string& content_binding,
                     const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());

    EXPECT_TRUE(reply.has_pca_request());
    AttestationCertificateRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));

    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_TRUE(pca_request.nvram_quotes().empty());

    EXPECT_EQ(cert_name, pca_request.identity_credential());
    EXPECT_EQ(DEVICE_SETUP_CERTIFICATE, pca_request.profile());
    EXPECT_FALSE(pca_request.has_origin());
    EXPECT_EQ(AttestationCertificateRequest::MetadataCase::
                  kDeviceSetupCertificateMetadata,
              pca_request.metadata_case());
    EXPECT_EQ(id, pca_request.device_setup_certificate_metadata().id());
    EXPECT_TRUE(pca_request.device_setup_certificate_metadata()
                    .has_timestamp_seconds());
    EXPECT_EQ(
        content_binding,
        pca_request.device_setup_certificate_metadata().content_binding());
    std::move(quit_closure).Run();
  };

  CreateCertificateRequestRequest request;
  request.set_certificate_profile(DEVICE_SETUP_CERTIFICATE);
  request.set_aca_type(aca_type_);
  const std::string kId = "random_id";
  const std::string kContentBinding = "content_binding";
  request.mutable_device_setup_certificate_request_metadata()->set_id(kId);
  request.mutable_device_setup_certificate_request_metadata()
      ->set_content_binding(kContentBinding);
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, kId, kContentBinding,
                     GetCertificateName(identity_, aca_type_), QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateEnrollmentCertificateRequestSuccess) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  EXPECT_CALL(mock_nvram_quoter_, GetListForIdentity())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({BOARD_ID, SN_BITS})));
  EXPECT_CALL(mock_nvram_quoter_, GetListForEnrollmentCertificate())
      .WillOnce(Return(
          std::vector<NVRAMQuoteType>({BOARD_ID, SN_BITS, RSU_DEVICE_ID})));
  // Identity will have baord id and sn bits quotes.
  EXPECT_CALL(mock_nvram_quoter_, Certify(RSU_DEVICE_ID, _, _));
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_pca_request());
    AttestationCertificateRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));
    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_EQ(ENTERPRISE_ENROLLMENT_CERTIFICATE, pca_request.profile());
    EXPECT_EQ(3, pca_request.nvram_quotes().size());
    EXPECT_EQ(kFakeBoardIdQuote,
              pca_request.nvram_quotes().at(BOARD_ID).quote());
    EXPECT_EQ(kFakeBoardIdQuotedData,
              pca_request.nvram_quotes().at(BOARD_ID).quoted_data());
    EXPECT_EQ(kFakeSnBitsQuote, pca_request.nvram_quotes().at(SN_BITS).quote());
    EXPECT_EQ(kFakeSnBitsQuotedData,
              pca_request.nvram_quotes().at(SN_BITS).quoted_data());
    EXPECT_EQ(kFakeRsuDeviceIdQuote,
              pca_request.nvram_quotes().at(RSU_DEVICE_ID).quote());
    EXPECT_EQ(kFakeRsuDeviceIdQuotedData,
              pca_request.nvram_quotes().at(RSU_DEVICE_ID).quoted_data());
    EXPECT_EQ(kFakeAttestedDeviceId, pca_request.attested_device_id());
    EXPECT_EQ(cert_name, pca_request.identity_credential());
    std::move(quit_closure).Run();
  };
  service_->set_attested_device_id(kFakeAttestedDeviceId);
  CreateCertificateRequestRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_ENROLLMENT_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest,
       CreateEnrollmentCertificateRequestContinueOnQuoteFailure) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  EXPECT_CALL(mock_nvram_quoter_, GetListForIdentity())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({BOARD_ID, SN_BITS})));
  EXPECT_CALL(mock_nvram_quoter_, GetListForEnrollmentCertificate())
      .WillOnce(Return(
          std::vector<NVRAMQuoteType>({BOARD_ID, SN_BITS, RSU_DEVICE_ID})));
  // Identity will have baord id and sn bits quotes.
  EXPECT_CALL(mock_nvram_quoter_, Certify(RSU_DEVICE_ID, _, _))
      .WillOnce(Return(false));
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_pca_request());
    AttestationCertificateRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));
    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_EQ(ENTERPRISE_ENROLLMENT_CERTIFICATE, pca_request.profile());
    EXPECT_EQ(2, pca_request.nvram_quotes().size());
    EXPECT_EQ(kFakeBoardIdQuote,
              pca_request.nvram_quotes().at(BOARD_ID).quote());
    EXPECT_EQ(kFakeBoardIdQuotedData,
              pca_request.nvram_quotes().at(BOARD_ID).quoted_data());
    EXPECT_EQ(kFakeSnBitsQuote, pca_request.nvram_quotes().at(SN_BITS).quote());
    EXPECT_EQ(kFakeSnBitsQuotedData,
              pca_request.nvram_quotes().at(SN_BITS).quoted_data());
    EXPECT_EQ(kFakeAttestedDeviceId, pca_request.attested_device_id());
    EXPECT_EQ(cert_name, pca_request.identity_credential());
    std::move(quit_closure).Run();
  };
  service_->set_attested_device_id(kFakeAttestedDeviceId);
  CreateCertificateRequestRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_ENROLLMENT_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateCertificateRequestInternalFailure) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  EXPECT_CALL(mock_crypto_utility_, GetRandom(_, _))
      .WillRepeatedly(Return(false));
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_pca_request());
    std::move(quit_closure).Run();
  };
  CreateCertificateRequestRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(request,
                                     base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateVtpmEkCertificateRequestSuccess) {
  service_->set_vtpm_ek_support(true);
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  EXPECT_CALL(mock_nvram_quoter_, GetListForVtpmEkCertificate())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({SN_BITS})));
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_pca_request());
    AttestationCertificateRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));
    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_EQ(ENTERPRISE_VTPM_EK_CERTIFICATE, pca_request.profile());
    EXPECT_EQ(1, pca_request.nvram_quotes().size());
    EXPECT_EQ(kFakeSnBitsQuote, pca_request.nvram_quotes().at(SN_BITS).quote());
    EXPECT_EQ(kFakeSnBitsQuotedData,
              pca_request.nvram_quotes().at(SN_BITS).quoted_data());
    EXPECT_EQ(kFakeAttestedDeviceId, pca_request.attested_device_id());
    EXPECT_EQ(cert_name, pca_request.identity_credential());
    std::move(quit_closure).Run();
  };
  service_->set_attested_device_id(kFakeAttestedDeviceId);
  CreateCertificateRequestRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_VTPM_EK_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest,
       CreateVtpmEkCertificateRequestSuccessMissingQuotesInidentity) {
  service_->set_vtpm_ek_support(true);
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  RemoveNvramQuotesFromIdentity(identity_);
  EXPECT_CALL(mock_nvram_quoter_, GetListForVtpmEkCertificate())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({SN_BITS})));
  EXPECT_CALL(mock_nvram_quoter_, Certify(SN_BITS, _, _));
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_pca_request());
    AttestationCertificateRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));
    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_EQ(ENTERPRISE_VTPM_EK_CERTIFICATE, pca_request.profile());
    EXPECT_EQ(1, pca_request.nvram_quotes().size());
    EXPECT_EQ(kFakeSnBitsQuote, pca_request.nvram_quotes().at(SN_BITS).quote());
    EXPECT_EQ(kFakeSnBitsQuotedData,
              pca_request.nvram_quotes().at(SN_BITS).quoted_data());
    EXPECT_EQ(kFakeAttestedDeviceId, pca_request.attested_device_id());
    EXPECT_EQ(cert_name, pca_request.identity_credential());
    std::move(quit_closure).Run();
  };
  service_->set_attested_device_id(kFakeAttestedDeviceId);
  CreateCertificateRequestRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_VTPM_EK_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest,
       CreateVtpmEkCertificateRequestFailureNoAttestedDeviceId) {
  service_->set_vtpm_ek_support(true);
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  RemoveNvramQuotesFromIdentity(identity_);
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  // Empty ADID should fail the operation.
  service_->set_attested_device_id("");
  CreateCertificateRequestRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_VTPM_EK_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest,
       CreateVtpmEkCertificateRequestFailureFailedToQuote) {
  service_->set_vtpm_ek_support(true);
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  RemoveNvramQuotesFromIdentity(identity_);
  EXPECT_CALL(mock_nvram_quoter_, GetListForVtpmEkCertificate())
      .WillOnce(Return(std::vector<NVRAMQuoteType>({SN_BITS})));
  EXPECT_CALL(mock_nvram_quoter_, Certify(SN_BITS, _, _))
      .WillOnce(Return(false));
  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  service_->set_attested_device_id(kFakeAttestedDeviceId);
  CreateCertificateRequestRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_VTPM_EK_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest,
       CreateVtpmEkCertificateRequestFailureNotSupported) {
  service_->set_vtpm_ek_support(false);
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  RemoveNvramQuotesFromIdentity(identity_);

  auto callback = [](const std::string& cert_name,
                     base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    std::move(quit_closure).Run();
  };
  service_->set_attested_device_id(kFakeAttestedDeviceId);
  CreateCertificateRequestRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_VTPM_EK_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(
      request,
      base::BindOnce(callback, GetCertificateName(identity_, aca_type_),
                     QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateCertificateRequestNotEnrolled) {
  // No identity certificate, so not enrolled.
  mock_database_.GetMutableProtobuf()->Clear();
  SetUpIdentity(identity_);
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateCertificateRequestReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_pca_request());
    std::move(quit_closure).Run();
  };
  CreateCertificateRequestRequest request;
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  service_->CreateCertificateRequest(request,
                                     base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, FinishCertificateRequestSuccess) {
  auto callback = [](base::OnceClosure quit_closure,
                     const FinishCertificateRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_certificate());
    std::move(quit_closure).Run();
  };
  AttestationCertificateRequest pca_request = GenerateCACertRequest();
  FinishCertificateRequestRequest request;
  request.set_username("user");
  request.set_key_label("label");
  request.set_pca_response(
      CreateCACertResponse(true, pca_request.message_id()));
  service_->FinishCertificateRequest(request,
                                     base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, FinishCertificateRequestInternalFailure) {
  EXPECT_CALL(mock_key_store_, Write(_, _, _)).WillRepeatedly(Return(false));
  auto callback = [](base::OnceClosure quit_closure,
                     const FinishCertificateRequestReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_certificate());
    std::move(quit_closure).Run();
  };
  AttestationCertificateRequest pca_request = GenerateCACertRequest();
  FinishCertificateRequestRequest request;
  request.set_username("user");
  request.set_key_label("label");
  request.set_pca_response(
      CreateCACertResponse(true, pca_request.message_id()));
  service_->FinishCertificateRequest(request,
                                     base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, FinishCertificateRequestWrongMessageId) {
  auto callback = [](base::OnceClosure quit_closure,
                     const FinishCertificateRequestReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_certificate());
    std::move(quit_closure).Run();
  };
  // Generate some request to populate pending_requests, but ignore its fields.
  GenerateCACertRequest();
  FinishCertificateRequestRequest request;
  request.set_username("user");
  request.set_key_label("label");
  request.set_pca_response(CreateCACertResponse(true, "wrong_id"));
  service_->FinishCertificateRequest(request,
                                     base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, FinishCertificateRequestServerFailure) {
  auto callback = [](base::OnceClosure quit_closure,
                     const FinishCertificateRequestReply& reply) {
    EXPECT_NE(STATUS_SUCCESS, reply.status());
    EXPECT_FALSE(reply.has_certificate());
    std::move(quit_closure).Run();
  };
  // Generate some request to populate pending_requests, but ignore its fields.
  GenerateCACertRequest();
  FinishCertificateRequestRequest request;
  request.set_username("user");
  request.set_key_label("label");
  request.set_pca_response(CreateCACertResponse(false, ""));
  service_->FinishCertificateRequest(request,
                                     base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateEnrollRequestSuccessWithoutAbeData) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  (*mock_database_.GetMutableProtobuf()
        ->mutable_credentials()
        ->mutable_encrypted_endorsement_credentials())[aca_type_]
      .set_wrapped_key("wrapped_key");
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateEnrollRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_pca_request());
    AttestationEnrollmentRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));
    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_EQ("wrapped_key",
              pca_request.encrypted_endorsement_credential().wrapped_key());
    EXPECT_EQ("public_key_tpm", pca_request.identity_public_key());
    EXPECT_EQ("pcr0", pca_request.pcr0_quote().quote());
    EXPECT_EQ("pcr1", pca_request.pcr1_quote().quote());
    EXPECT_FALSE(pca_request.has_enterprise_enrollment_nonce());
    std::move(quit_closure).Run();
  };
  CreateEnrollRequestRequest request;
  request.set_aca_type(aca_type_);
  service_->CreateEnrollRequest(request,
                                base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateEnrollRequestSuccessWithEmptyAbeData) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  (*mock_database_.GetMutableProtobuf()
        ->mutable_credentials()
        ->mutable_encrypted_endorsement_credentials())[aca_type_]
      .set_wrapped_key("wrapped_key");
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateEnrollRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_pca_request());
    AttestationEnrollmentRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));
    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_EQ("wrapped_key",
              pca_request.encrypted_endorsement_credential().wrapped_key());
    EXPECT_EQ("public_key_tpm", pca_request.identity_public_key());
    EXPECT_EQ("pcr0", pca_request.pcr0_quote().quote());
    EXPECT_EQ("pcr1", pca_request.pcr1_quote().quote());
    EXPECT_FALSE(pca_request.has_enterprise_enrollment_nonce());
    std::move(quit_closure).Run();
  };
  brillo::SecureBlob abe_data;
  service_->set_abe_data(&abe_data);
  CreateEnrollRequestRequest request;
  request.set_aca_type(aca_type_);
  service_->CreateEnrollRequest(request,
                                base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, CreateEnrollRequestSuccessWithAbeData) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  (*mock_database_.GetMutableProtobuf()
        ->mutable_credentials()
        ->mutable_encrypted_endorsement_credentials())[aca_type_]
      .set_wrapped_key("wrapped_key");
  auto callback = [](base::OnceClosure quit_closure,
                     const CreateEnrollRequestReply& reply) {
    EXPECT_EQ(STATUS_SUCCESS, reply.status());
    EXPECT_TRUE(reply.has_pca_request());
    AttestationEnrollmentRequest pca_request;
    EXPECT_TRUE(pca_request.ParseFromString(reply.pca_request()));
    EXPECT_EQ(GetTpmVersionUnderTest(), pca_request.tpm_version());
    EXPECT_EQ("wrapped_key",
              pca_request.encrypted_endorsement_credential().wrapped_key());
    EXPECT_EQ("public_key_tpm", pca_request.identity_public_key());
    EXPECT_EQ("pcr0", pca_request.pcr0_quote().quote());
    EXPECT_EQ("pcr1", pca_request.pcr1_quote().quote());
    EXPECT_TRUE(pca_request.has_enterprise_enrollment_nonce());

    // Mocked CryptoUtility->HmacSha256 returns always a zeroed buffer.
    EXPECT_EQ(std::string(32, '\0'), pca_request.enterprise_enrollment_nonce());
    std::move(quit_closure).Run();
  };

  CreateEnrollRequestRequest request;
  request.set_aca_type(aca_type_);
  brillo::SecureBlob abe_data(0xCA, 32);
  service_->set_abe_data(&abe_data);
  service_->CreateEnrollRequest(request,
                                base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, EnrollSuccess) {
  SetUpIdentity(identity_);
  (*mock_database_.GetMutableProtobuf()
        ->mutable_credentials()
        ->mutable_encrypted_endorsement_credentials())[aca_type_]
      .set_wrapped_key("wrapped_key");
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    quit_closure.Run();
  };

  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(1);

  EnrollRequest request;
  request.set_aca_type(aca_type_);
  service_->Enroll(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, EnrollSuccessNoop) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  (*mock_database_.GetMutableProtobuf()
        ->mutable_credentials()
        ->mutable_encrypted_endorsement_credentials())[aca_type_]
      .set_wrapped_key("wrapped_key");
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    quit_closure.Run();
  };
  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(0);
  EnrollRequest request;
  request.set_aca_type(aca_type_);
  service_->Enroll(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, EnrollSuccessForced) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  (*mock_database_.GetMutableProtobuf()
        ->mutable_credentials()
        ->mutable_encrypted_endorsement_credentials())[aca_type_]
      .set_wrapped_key("wrapped_key");
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    quit_closure.Run();
  };

  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(1);

  EnrollRequest request;
  request.set_aca_type(aca_type_);
  request.set_forced(true);
  service_->Enroll(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, EnrollFailureNoIdentity) {
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
    quit_closure.Run();
  };
  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(0);
  EnrollRequest request;
  request.set_aca_type(aca_type_);
  service_->Enroll(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, EnrollFailureBadPcaAgentStatus) {
  SetUpIdentity(identity_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
    quit_closure.Run();
  };

  fake_pca_agent_proxy_.SetEnrollDBusError();
  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(1);

  EnrollRequest request;
  request.set_aca_type(aca_type_);
  service_->Enroll(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, EnrollFailureBadPcaAgentResponse) {
  SetUpIdentity(identity_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_INVALID_PARAMETER);
    quit_closure.Run();
  };
  fake_pca_agent_proxy_.SetBadEnrollStatus(STATUS_INVALID_PARAMETER);
  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(1);

  EnrollRequest request;
  request.set_aca_type(aca_type_);
  service_->Enroll(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, EnrollFailureBadPcaServerResponse) {
  SetUpIdentity(identity_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_REQUEST_DENIED_BY_CA);
    quit_closure.Run();
  };

  fake_pca_agent_proxy_.SetBadEnrollPcaResponse();
  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(1);

  EnrollRequest request;
  request.set_aca_type(aca_type_);
  service_->Enroll(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetCertificateSuccess) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    EXPECT_TRUE(reply.has_public_key());
    EXPECT_TRUE(reply.has_certificate());
    EXPECT_TRUE(reply.has_certified_key_credential());
    EXPECT_TRUE(reply.has_key_blob());
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(Return(false));

  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);

  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetDeviceSetupCertificateRequestSuccess) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);

  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    EXPECT_TRUE(reply.has_public_key());
    EXPECT_TRUE(reply.has_certificate());
    EXPECT_TRUE(reply.has_certified_key_credential());
    EXPECT_TRUE(reply.has_key_blob());
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_key_label("label");
  request.set_certificate_profile(DEVICE_SETUP_CERTIFICATE);
  request.mutable_device_setup_certificate_request_metadata()->set_id(
      "random_id");
  request.mutable_device_setup_certificate_request_metadata()
      ->set_content_binding("content_binding");

  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);

  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetCertificateSuccessNoop) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    EXPECT_TRUE(reply.has_public_key());
    EXPECT_TRUE(reply.has_certificate());
    EXPECT_TRUE(reply.has_certified_key_credential());
    EXPECT_TRUE(reply.has_key_blob());
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(DoAll(SetArgPointee<2>(GenerateSerializedFakeCertifiedKey()),
                      Return(true)));
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(0);
  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetCertificateSuccessSavedBadPublicKey) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(DoAll(SetArgPointee<2>(GenerateSerializedFakeCertifiedKey()),
                      Return(true)));
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(0);
  EXPECT_CALL(mock_crypto_utility_, GetRSASubjectPublicKeyInfo(_, _))
      .WillOnce(Return(false));
  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetCertificateSuccessForced) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    EXPECT_TRUE(reply.has_certificate());
    EXPECT_TRUE(reply.has_certified_key_credential());
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  request.set_forced(true);
  // We shouldn't even check the key store.
  EXPECT_CALL(mock_key_store_, Read("user", "label", _)).Times(0);

  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);

  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetCertificateFailureNoIdentity) {
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(0);
  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetCertificateFailureBadPcaAgentStatus) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(Return(false));
  brillo::ErrorPtr err = brillo::Error::Create(base::Location(), "", "", "");
  fake_pca_agent_proxy_.SetGetCertificateDBusError();
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);

  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetCertificateFailureBadPcaAgentResponse) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_NOT_AVAILABLE);
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(Return(false));

  pca_agent::GetCertificateReply reply;
  fake_pca_agent_proxy_.SetBadGetCertificateStatus(STATUS_NOT_AVAILABLE);
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);

  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, GetCertificateFailureBadPcaServerResponse) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_REQUEST_DENIED_BY_CA);
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(Return(false));

  fake_pca_agent_proxy_.SetBadGetCertificatePcaResponse();
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);

  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, AttestationFlowSuccess) {
  SetUpIdentity(identity_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    EXPECT_TRUE(reply.has_certificate());
    EXPECT_TRUE(reply.has_public_key());
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  request.set_shall_trigger_enrollment(true);
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(Return(false));

  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(1);
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);

  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, AttestationFlowBadPublicKey) {
  SetUpIdentity(identity_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  request.set_shall_trigger_enrollment(true);
  EXPECT_CALL(mock_key_store_, Read("user", "label", _))
      .WillOnce(Return(false));

  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(1);
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);
  EXPECT_CALL(mock_crypto_utility_, GetRSASubjectPublicKeyInfo(_, _))
      .WillOnce(Return(false));

  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

TEST_P(AttestationServiceTest, AttestationFlowFailureNotEnrolled) {
  SetUpIdentity(identity_);
  auto callback = [](const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
    quit_closure.Run();
  };
  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(0);
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(0);
  service_->GetCertificate(request, base::BindOnce(callback, QuitClosure()));
  Run();
}

// the extensive unittests that are worth being kept but unable to be in the
// standard set of unittest for any reason, e.g., flakiness.
#ifdef EXTENSIVE_UNITTEST

TEST_P(AttestationServiceTest, EnrollSuccessQueued) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  (*mock_database_.GetMutableProtobuf()
        ->mutable_credentials()
        ->mutable_encrypted_endorsement_credentials())[aca_type_]
      .set_wrapped_key("wrapped_key");

  // Offset by 1; for enrollment request the request under process doesn't
  // count.
  int request_count = service_->kEnrollmentRequestLimit + 1;
  auto callback = [](int* count, const base::RepeatingClosure& quit_closure,
                     const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    *count -= 1;
    if (*count == 0) {
      quit_closure.Run();
    }
  };

  auto failure_callback = [](const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
  };

  fake_pca_agent_proxy_.SetEnrollCallbackDelay(base::Milliseconds(125));
  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(1);

  EnrollRequest request;
  request.set_aca_type(aca_type_);
  request.set_forced(true);
  for (int i = 0; i < request_count; ++i) {
    service_->Enroll(request,
                     base::BindOnce(callback, &request_count, QuitClosure()));
  }
  // Reaching the limit, this request should get error.
  service_->Enroll(request, base::BindOnce(failure_callback));
  Run();
  ASSERT_EQ(request_count, 0);
}

TEST_P(AttestationServiceTest, EnrollFailureQueued) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);
  (*mock_database_.GetMutableProtobuf()
        ->mutable_credentials()
        ->mutable_encrypted_endorsement_credentials())[aca_type_]
      .set_wrapped_key("wrapped_key");

  // Offset by 1; for enrollment request the request under process doesn't
  // count.
  int request_count = service_->kEnrollmentRequestLimit + 1;
  auto callback = [](int* count, const base::RepeatingClosure& quit_closure,
                     const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_INVALID_PARAMETER);
    *count -= 1;
    if (*count == 0) {
      quit_closure.Run();
    }
  };

  auto failure_callback = [](const EnrollReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
  };

  fake_pca_agent_proxy_.SetBadEnrollStatus(STATUS_INVALID_PARAMETER);
  fake_pca_agent_proxy_.SetEnrollCallbackDelay(base::Milliseconds(125));
  EXPECT_CALL(fake_pca_agent_proxy_, EnrollAsync(_, _, _, _)).Times(1);

  EnrollRequest request;
  request.set_aca_type(aca_type_);
  request.set_forced(true);
  for (int i = 0; i < request_count; ++i) {
    service_->Enroll(request,
                     base::BindOnce(callback, &request_count, QuitClosure()));
  }
  // Reaching the limit, this request should get error.
  service_->Enroll(request, base::BindOnce(failure_callback));
  Run();
  ASSERT_EQ(request_count, 0);
}

TEST_P(AttestationServiceTest, GetCertificateSuccessQueued) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);

  int request_count = service_->kCertificateRequestAliasLimit;
  auto callback = [](int* count, const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_SUCCESS);
    *count -= 1;
    if (*count == 0) {
      quit_closure.Run();
    }
  };
  auto failure_callback = [](const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
  };

  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  request.set_forced(true);
  // We shouldn't even check the key store.
  EXPECT_CALL(mock_key_store_, Read("user", "label", _)).Times(0);

  fake_pca_agent_proxy_.SetGetCertificateCallbackDelay(base::Milliseconds(125));
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);

  for (int i = 0; i < request_count; ++i) {
    service_->GetCertificate(
        request, base::BindOnce(callback, &request_count, QuitClosure()));
  }
  // This should due to alias contention.
  service_->GetCertificate(request, base::BindOnce(failure_callback));
  Run();
  ASSERT_EQ(request_count, 0);
}

TEST_P(AttestationServiceTest, GetCertificateFailureQueued) {
  SetUpIdentity(identity_);
  SetUpIdentityCertificate(identity_, aca_type_);

  int request_count = service_->kCertificateRequestAliasLimit;
  auto callback = [](int* count, const base::RepeatingClosure& quit_closure,
                     const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_NOT_AVAILABLE);
    *count -= 1;
    if (*count == 0) {
      quit_closure.Run();
    }
  };
  auto failure_callback = [](const GetCertificateReply& reply) {
    EXPECT_EQ(reply.status(), STATUS_UNEXPECTED_DEVICE_ERROR);
  };

  GetCertificateRequest request;
  request.set_aca_type(aca_type_);
  request.set_certificate_profile(ENTERPRISE_MACHINE_CERTIFICATE);
  request.set_username("user");
  request.set_request_origin("origin");
  request.set_key_label("label");
  request.set_forced(true);
  // We shouldn't even check the key store.
  EXPECT_CALL(mock_key_store_, Read("user", "label", _)).Times(0);

  fake_pca_agent_proxy_.SetBadGetCertificateStatus(STATUS_NOT_AVAILABLE);
  fake_pca_agent_proxy_.SetGetCertificateCallbackDelay(base::Milliseconds(125));
  EXPECT_CALL(fake_pca_agent_proxy_, GetCertificateAsync(_, _, _, _)).Times(1);

  for (int i = 0; i < request_count; ++i) {
    service_->GetCertificate(
        request, base::BindOnce(callback, &request_count, QuitClosure()));
  }
  // This should due to alias contention.
  service_->GetCertificate(request, base::BindOnce(failure_callback));
  Run();
  ASSERT_EQ(request_count, 0);
}

#endif

INSTANTIATE_TEST_SUITE_P(AcaType,
                         AttestationServiceTest,
                         ::testing::Values(DEFAULT_ACA, TEST_ACA));

}  // namespace attestation
