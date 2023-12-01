// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "u2fd/u2f_command_processor_vendor.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/containers/span.h>
#include <base/strings/string_number_conversions.h>
#include <base/test/task_environment.h>
#include <base/time/time.h>
#include <brillo/dbus/mock_dbus_method_response.h>
#include <libhwsec/frontend/u2fd/mock_vendor_frontend.h>
#include <libhwsec/frontend/u2fd/vendor_frontend.h>
#include <libhwsec-foundation/error/testing_helper.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "u2fd/client/util.h"

namespace u2f {
namespace {

using GenerateResult = hwsec::u2f::GenerateResult;
using Signature = hwsec::u2f::Signature;
using ConsumeMode = hwsec::u2f::ConsumeMode;
using UserPresenceMode = hwsec::u2f::UserPresenceMode;

using hwsec::TPMError;
using hwsec::TPMRetryAction;
using hwsec_foundation::status::MakeStatus;

using hwsec_foundation::error::testing::IsOkAndHolds;
using hwsec_foundation::error::testing::NotOk;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnOk;
using hwsec_foundation::error::testing::ReturnValue;

using ::testing::_;
using ::testing::ByMove;
using ::testing::DoAll;
using ::testing::Matcher;
using ::testing::MatchesRegex;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

constexpr base::TimeDelta kVerificationTimeout = base::Seconds(10);
constexpr base::TimeDelta kRequestPresenceDelay = base::Milliseconds(500);
constexpr int kMaxRetries = kVerificationTimeout / kRequestPresenceDelay;

constexpr char kCredentialSecret[65] = {[0 ... 63] = 'E', '\0'};
// Stub RP id.
constexpr char kRpId[] = "example.com";
// Wrong RP id is used to test app id extension path.
constexpr char kWrongRpId[] = "wrong.com";

// Example of a cert that would be returned by cr50.
constexpr char kStubG2fCert[] =
    "308201363081DDA0030201020210442D32429223D041240350303716EE6B300A06082A8648"
    "CE3D040302300F310D300B06035504031304637235303022180F3230303030313031303030"
    "3030305A180F32303939313233313233353935395A300F310D300B06035504031304637235"
    "303059301306072A8648CE3D020106082A8648CE3D030107034200045165719A9975F6FD30"
    "CC2516C22FE841F65F9D2EE7B8B72F76807AEBD8CA3376005C7FA86453E4B10DB7BFAD5D2B"
    "D00DB4A7C4845AD06D686ACD0252387618ECA31730153013060B2B0601040182E51C020101"
    "040403020308300A06082A8648CE3D0403020348003045022100F09976F373920FEF8205C4"
    "B1FB1DA21EB9F3F176B7DF433A1ADE0F3F38B721960220179D9B9051BFCCCC90BA6BB42B86"
    "111D7A9C4FB56DFD39FB426081DD027AD609";

constexpr hwsec::u2f::Config kConfig{
    .up_only_kh_size = 20,
    .kh_size = 30,
};

std::vector<uint8_t> GetRpIdHash() {
  return util::Sha256(std::string(kRpId));
}

std::vector<uint8_t> GetWrongRpIdHash() {
  return util::Sha256(std::string(kWrongRpId));
}

std::vector<uint8_t> GetHashToSign() {
  return std::vector<uint8_t>(32, 0xcd);
}

brillo::SecureBlob GetUserSecret() {
  return brillo::SecureBlob(32, 'E');
}

std::vector<uint8_t> GetCredId() {
  return std::vector<uint8_t>(kConfig.up_only_kh_size, 0xFD);
}

std::vector<uint8_t> GetVersionedCredId() {
  return std::vector<uint8_t>(kConfig.kh_size, 0xFD);
}

std::vector<uint8_t> GetAuthTimeSecretHash() {
  return std::vector<uint8_t>(32, 0xFD);
}

std::vector<uint8_t> GetChallenge() {
  return std::vector<uint8_t>(32, 0xDD);
}

std::vector<uint8_t> GetSigR() {
  return std::vector<uint8_t>(32, 0xEE);
}

std::vector<uint8_t> GetSigS() {
  return std::vector<uint8_t>(32, 0xFF);
}

std::vector<uint8_t> GetStubG2fCert() {
  std::vector<uint8_t> cert;
  base::HexStringToBytes(kStubG2fCert, &cert);
  return cert;
}

brillo::SecureBlob ArrayToSecureBlob(const char* array) {
  brillo::SecureBlob blob;
  CHECK(brillo::SecureBlob::HexStringToSecureBlob(array, &blob));
  return blob;
}

}  // namespace

class FakePublicKey : public hwsec::u2f::PublicKey {
 public:
  explicit FakePublicKey(brillo::Blob raw) : data_(std::move(raw)) {
    CHECK_EQ(data_.size(), 65);
  }

  base::span<const uint8_t> x() const override {
    return base::make_span(data_.data() + 1, 32u);
  }

  base::span<const uint8_t> y() const override {
    return base::make_span(data_.data() + 33, 32u);
  }

  const brillo::Blob& raw() const override { return data_; }

 private:
  brillo::Blob data_;
};

class U2fCommandProcessorVendorTest : public ::testing::Test {
 public:
  void SetUp() override {
    auto mock_u2f_frontend = std::make_unique<hwsec::MockU2fVendorFrontend>();
    mock_u2f_frontend_ = mock_u2f_frontend.get();
    EXPECT_CALL(*mock_u2f_frontend_, GetConfig)
        .WillRepeatedly(ReturnValue(kConfig));
    processor_ = std::make_unique<U2fCommandProcessorVendor>(
        std::move(mock_u2f_frontend), [this]() {
          presence_requested_count_++;
          task_environment_.FastForwardBy(kRequestPresenceDelay);
        });
  }

  void TearDown() override {
    EXPECT_EQ(presence_requested_expected_, presence_requested_count_);
  }

 protected:
  static std::vector<uint8_t> GetCredPubKeyRaw() {
    return std::vector<uint8_t>(65, 0xAB);
  }

  static std::vector<uint8_t> GetCredPubKeyCbor() {
    return U2fCommandProcessorVendor::EncodeCredentialPublicKeyInCBOR(
        std::vector<uint8_t>(32, 0xAB), std::vector<uint8_t>(32, 0xAB));
  }

  hwsec::StatusOr<int> CallAndWaitForPresence(
      std::function<hwsec::StatusOr<int>()> fn) {
    return processor_->CallAndWaitForPresenceForTest(fn);
  }

  bool PresenceRequested() { return presence_requested_count_ > 0; }

  MakeCredentialResponse::MakeCredentialStatus U2fGenerate(
      PresenceRequirement presence_requirement,
      bool uv_compatible,
      const brillo::Blob* auth_time_secret_hash,
      std::vector<uint8_t>* credential_id,
      CredentialPublicKey* credential_pubkey) {
    // U2fGenerate expects some output fields to be non-null, but we
    // want to support nullptr output fields in this helper method.
    std::vector<uint8_t> cred_id;
    CredentialPublicKey pubkey;
    if (!credential_id) {
      credential_id = &cred_id;
    }
    if (!credential_pubkey) {
      credential_pubkey = &pubkey;
    }
    return processor_->U2fGenerate(
        GetRpIdHash(), ArrayToSecureBlob(kCredentialSecret),
        presence_requirement, uv_compatible, auth_time_secret_hash,
        credential_id, credential_pubkey, nullptr);
  }

  GetAssertionResponse::GetAssertionStatus U2fSign(
      const std::vector<uint8_t>& hash_to_sign,
      const std::vector<uint8_t>& credential_id,
      PresenceRequirement presence_requirement,
      std::vector<uint8_t>* signature) {
    return processor_->U2fSign(GetRpIdHash(), hash_to_sign, credential_id,
                               ArrayToSecureBlob(kCredentialSecret), nullptr,
                               presence_requirement, signature);
  }

  HasCredentialsResponse::HasCredentialsStatus U2fSignCheckOnly(
      const std::vector<uint8_t>& rp_id_hash,
      const std::vector<uint8_t>& credential_id) {
    return processor_->U2fSignCheckOnly(rp_id_hash, credential_id,
                                        ArrayToSecureBlob(kCredentialSecret),
                                        nullptr);
  }

  MakeCredentialResponse::MakeCredentialStatus G2fAttest(
      const std::vector<uint8_t>& rp_id_hash,
      const brillo::SecureBlob& credential_secret,
      const std::vector<uint8_t>& challenge,
      const std::vector<uint8_t>& credential_public_key,
      const std::vector<uint8_t>& credential_id,
      std::vector<uint8_t>* cert_out,
      std::vector<uint8_t>* signature_out) {
    return processor_->G2fAttest(rp_id_hash, credential_secret, challenge,
                                 credential_public_key, credential_id, cert_out,
                                 signature_out);
  }

  bool G2fSoftwareAttest(const std::vector<uint8_t>& rp_id_hash,
                         const std::vector<uint8_t>& challenge,
                         const std::vector<uint8_t>& credential_public_key,
                         const std::vector<uint8_t>& credential_id,
                         std::vector<uint8_t>* cert_out,
                         std::vector<uint8_t>* signature_out) {
    return processor_->G2fSoftwareAttest(rp_id_hash, challenge,
                                         credential_public_key, credential_id,
                                         cert_out, signature_out);
  }

  int presence_requested_expected_ = 0;
  hwsec::MockU2fVendorFrontend* mock_u2f_frontend_;

 private:
  int presence_requested_count_ = 0;
  base::test::TaskEnvironment task_environment_{
      base::test::TaskEnvironment::TimeSource::MOCK_TIME};

  std::unique_ptr<U2fCommandProcessorVendor> processor_;
};

namespace {

TEST_F(U2fCommandProcessorVendorTest, CallAndWaitForPresenceDirectSuccess) {
  // If presence is already available, we won't request it.
  EXPECT_THAT(CallAndWaitForPresence([]() { return 0; }), IsOkAndHolds(0));
  presence_requested_expected_ = 0;
}

TEST_F(U2fCommandProcessorVendorTest, CallAndWaitForPresenceRequestSuccess) {
  EXPECT_THAT(CallAndWaitForPresence([this]() -> hwsec::StatusOr<int> {
                if (PresenceRequested())
                  return 0;
                return MakeStatus<TPMError>("Not allowed",
                                            TPMRetryAction::kUserPresence);
              }),
              IsOkAndHolds(0));
  presence_requested_expected_ = 1;
}

TEST_F(U2fCommandProcessorVendorTest, CallAndWaitForPresenceTimeout) {
  base::TimeTicks verification_start = base::TimeTicks::Now();
  EXPECT_THAT(CallAndWaitForPresence([]() {
                return MakeStatus<TPMError>("Not allowed",
                                            TPMRetryAction::kUserPresence);
              }),
              NotOk());
  EXPECT_GE(base::TimeTicks::Now() - verification_start, kVerificationTimeout);
  presence_requested_expected_ = kMaxRetries;
}

TEST_F(U2fCommandProcessorVendorTest,
       U2fGenerateVersionedNoAuthTimeSecretHash) {
  EXPECT_EQ(U2fGenerate(PresenceRequirement::kPowerButton,
                        /* uv_compatible = */ true, nullptr, nullptr, nullptr),
            MakeCredentialResponse::INTERNAL_ERROR);
}

TEST_F(U2fCommandProcessorVendorTest, U2fGenerateVersionedSuccessUserPresence) {
  EXPECT_CALL(*mock_u2f_frontend_, Generate(_, _, ConsumeMode::kConsume,
                                            UserPresenceMode::kRequired, _))
      .WillOnce(
          ReturnError<TPMError>("Not allowed", TPMRetryAction::kUserPresence))
      .WillOnce([](const auto&, const auto&, auto, auto, const auto&) {
        return GenerateResult{
            .public_key = std::make_unique<FakePublicKey>(
                U2fCommandProcessorVendorTest::GetCredPubKeyRaw()),
            .key_handle = GetVersionedCredId(),
        };
      });
  std::vector<uint8_t> cred_id;
  CredentialPublicKey cred_pubkey;
  auto auth_time_secret_hash = GetAuthTimeSecretHash();
  EXPECT_EQ(U2fGenerate(PresenceRequirement::kPowerButton,
                        /* uv_compatible = */ true, &auth_time_secret_hash,
                        &cred_id, &cred_pubkey),
            MakeCredentialResponse::SUCCESS);
  EXPECT_EQ(cred_id, GetVersionedCredId());
  EXPECT_EQ(cred_pubkey.cbor,
            U2fCommandProcessorVendorTest::GetCredPubKeyCbor());
  EXPECT_EQ(cred_pubkey.raw, U2fCommandProcessorVendorTest::GetCredPubKeyRaw());
  presence_requested_expected_ = 1;
}

TEST_F(U2fCommandProcessorVendorTest, U2fGenerateVersionedNoUserPresence) {
  EXPECT_CALL(*mock_u2f_frontend_, Generate(_, _, ConsumeMode::kConsume,
                                            UserPresenceMode::kRequired, _))
      .WillRepeatedly(
          ReturnError<TPMError>("Not allowed", TPMRetryAction::kUserPresence));
  auto auth_time_secret_hash = GetAuthTimeSecretHash();
  EXPECT_EQ(U2fGenerate(PresenceRequirement::kPowerButton,
                        /* uv_compatible = */ true, &auth_time_secret_hash,
                        nullptr, nullptr),
            MakeCredentialResponse::VERIFICATION_FAILED);
  presence_requested_expected_ = kMaxRetries;
}

TEST_F(U2fCommandProcessorVendorTest, U2fGenerateSuccessUserPresence) {
  EXPECT_CALL(*mock_u2f_frontend_,
              GenerateUserPresenceOnly(_, _, ConsumeMode::kConsume,
                                       UserPresenceMode::kRequired))
      .WillOnce(
          ReturnError<TPMError>("Not allowed", TPMRetryAction::kUserPresence))
      .WillOnce([](const auto&, const auto&, auto, auto) {
        return GenerateResult{
            .public_key = std::make_unique<FakePublicKey>(
                U2fCommandProcessorVendorTest::GetCredPubKeyRaw()),
            .key_handle = GetCredId(),
        };
      });
  std::vector<uint8_t> cred_id;
  CredentialPublicKey cred_pubkey;
  EXPECT_EQ(
      U2fGenerate(PresenceRequirement::kPowerButton,
                  /* uv_compatible = */ false, nullptr, &cred_id, &cred_pubkey),
      MakeCredentialResponse::SUCCESS);
  EXPECT_EQ(cred_id, GetCredId());
  EXPECT_EQ(cred_pubkey.cbor,
            U2fCommandProcessorVendorTest::GetCredPubKeyCbor());
  EXPECT_EQ(cred_pubkey.raw, U2fCommandProcessorVendorTest::GetCredPubKeyRaw());
  presence_requested_expected_ = 1;
}

TEST_F(U2fCommandProcessorVendorTest, U2fGenerateNoUserPresence) {
  EXPECT_CALL(*mock_u2f_frontend_,
              GenerateUserPresenceOnly(_, _, ConsumeMode::kConsume,
                                       UserPresenceMode::kRequired))
      .WillRepeatedly(
          ReturnError<TPMError>("Not allowed", TPMRetryAction::kUserPresence));
  EXPECT_EQ(U2fGenerate(PresenceRequirement::kPowerButton,
                        /* uv_compatible = */ false, nullptr, nullptr, nullptr),
            MakeCredentialResponse::VERIFICATION_FAILED);
  presence_requested_expected_ = kMaxRetries;
}

TEST_F(U2fCommandProcessorVendorTest,
       U2fGenerateVersionedSuccessUserVerification) {
  EXPECT_CALL(*mock_u2f_frontend_, Generate(_, _, ConsumeMode::kNoConsume,
                                            UserPresenceMode::kNotRequired, _))
      .WillOnce([](const auto&, const auto&, auto, auto, const auto&) {
        return GenerateResult{
            .public_key = std::make_unique<FakePublicKey>(
                U2fCommandProcessorVendorTest::GetCredPubKeyRaw()),
            .key_handle = GetVersionedCredId(),
        };
      });
  std::vector<uint8_t> cred_id;
  CredentialPublicKey cred_pubkey;
  auto auth_time_secret_hash = GetAuthTimeSecretHash();
  // UI has verified the user so do not require presence.
  EXPECT_EQ(U2fGenerate(PresenceRequirement::kNone, /* uv_compatible = */ true,
                        &auth_time_secret_hash, &cred_id, &cred_pubkey),
            MakeCredentialResponse::SUCCESS);
  EXPECT_EQ(cred_id, GetVersionedCredId());
  EXPECT_EQ(cred_pubkey.cbor,
            U2fCommandProcessorVendorTest::GetCredPubKeyCbor());
  EXPECT_EQ(cred_pubkey.raw, U2fCommandProcessorVendorTest::GetCredPubKeyRaw());
}

TEST_F(U2fCommandProcessorVendorTest, U2fSignPresenceNoPresence) {
  EXPECT_CALL(*mock_u2f_frontend_,
              SignUserPresenceOnly(_, _, _, ConsumeMode::kConsume,
                                   UserPresenceMode::kRequired, _))
      .WillRepeatedly(
          ReturnError<TPMError>("Not allowed", TPMRetryAction::kUserPresence));
  std::vector<uint8_t> signature;
  EXPECT_EQ(U2fSign(GetHashToSign(), GetCredId(),
                    PresenceRequirement::kPowerButton, &signature),
            MakeCredentialResponse::VERIFICATION_FAILED);
  presence_requested_expected_ = kMaxRetries;
}

TEST_F(U2fCommandProcessorVendorTest, U2fSignPresenceSuccess) {
  EXPECT_CALL(*mock_u2f_frontend_,
              SignUserPresenceOnly(_, _, _, ConsumeMode::kConsume,
                                   UserPresenceMode::kRequired, _))
      .WillOnce(
          ReturnError<TPMError>("Not allowed", TPMRetryAction::kUserPresence))
      .WillOnce(ReturnValue(Signature{
          .r = GetSigR(),
          .s = GetSigS(),
      }));
  std::vector<uint8_t> signature;
  EXPECT_EQ(U2fSign(GetHashToSign(), GetCredId(),
                    PresenceRequirement::kPowerButton, &signature),
            MakeCredentialResponse::SUCCESS);
  EXPECT_EQ(signature, util::SignatureToDerBytes(GetSigR(), GetSigS()));
  presence_requested_expected_ = 1;
}

TEST_F(U2fCommandProcessorVendorTest, U2fSignVersionedSuccess) {
  brillo::Blob credential_id(GetVersionedCredId());
  EXPECT_CALL(*mock_u2f_frontend_, Sign(_, _, _, _, ConsumeMode::kNoConsume,
                                        UserPresenceMode::kNotRequired, _))
      .WillOnce(ReturnValue(Signature{
          .r = GetSigR(),
          .s = GetSigS(),
      }));
  std::vector<uint8_t> signature;
  EXPECT_EQ(U2fSign(GetHashToSign(), credential_id, PresenceRequirement::kNone,
                    &signature),
            MakeCredentialResponse::SUCCESS);
  EXPECT_EQ(signature, util::SignatureToDerBytes(GetSigR(), GetSigS()));
}

TEST_F(U2fCommandProcessorVendorTest, U2fSignCheckOnlyWrongRpIdHash) {
  EXPECT_CALL(*mock_u2f_frontend_, CheckUserPresenceOnly)
      .WillOnce(ReturnError<TPMError>("Not allowed", TPMRetryAction::kNoRetry));
  EXPECT_EQ(U2fSignCheckOnly(GetWrongRpIdHash(), GetCredId()),
            HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID);
}

TEST_F(U2fCommandProcessorVendorTest, U2fSignCheckOnlySuccess) {
  EXPECT_CALL(*mock_u2f_frontend_, CheckUserPresenceOnly)
      .WillOnce(ReturnOk<TPMError>());
  EXPECT_EQ(U2fSignCheckOnly(GetRpIdHash(), GetCredId()),
            HasCredentialsResponse::SUCCESS);
}

TEST_F(U2fCommandProcessorVendorTest, U2fSignCheckOnlyVersionedSuccess) {
  brillo::Blob credential_id(GetVersionedCredId());
  EXPECT_CALL(*mock_u2f_frontend_, Check).WillOnce(ReturnOk<TPMError>());
  EXPECT_EQ(U2fSignCheckOnly(GetRpIdHash(), credential_id),
            HasCredentialsResponse::SUCCESS);
}

TEST_F(U2fCommandProcessorVendorTest, U2fSignCheckOnlyWrongLength) {
  std::vector<uint8_t> wrong_length_key_handle(kConfig.up_only_kh_size + 1,
                                               0xab);
  EXPECT_EQ(U2fSignCheckOnly(GetRpIdHash(), wrong_length_key_handle),
            HasCredentialsResponse::UNKNOWN_CREDENTIAL_ID);
}

TEST_F(U2fCommandProcessorVendorTest, G2fAttestSuccess) {
  EXPECT_CALL(*mock_u2f_frontend_, GetG2fCert)
      .WillOnce(ReturnValue(GetStubG2fCert()));
  EXPECT_CALL(*mock_u2f_frontend_, G2fAttest)
      .WillOnce(ReturnValue(Signature{
          .r = GetSigR(),
          .s = GetSigS(),
      }));
  auto secret = GetUserSecret();
  brillo::Blob cert_out, signature_out;
  EXPECT_EQ(G2fAttest(GetRpIdHash(), secret, GetChallenge(), GetCredPubKeyRaw(),
                      GetCredId(), &cert_out, &signature_out),
            MakeCredentialResponse::SUCCESS);
}

TEST_F(U2fCommandProcessorVendorTest, G2fSoftwareAttestSuccess) {
  EXPECT_CALL(*mock_u2f_frontend_, GetG2fAttestData)
      .WillOnce(ReturnValue(brillo::Blob(30)));
  auto secret = GetUserSecret();
  brillo::Blob cert_out, signature_out;
  EXPECT_TRUE(G2fSoftwareAttest(GetRpIdHash(), GetChallenge(),
                                GetCredPubKeyRaw(), GetCredId(), &cert_out,
                                &signature_out));
}

}  // namespace

}  // namespace u2f
