// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Tests for the ChallengeCredentialsHelperImpl class.

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/functional/bind.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/challenge_credentials/challenge_credentials_constants.h"
#include "cryptohome/challenge_credentials/challenge_credentials_helper_impl.h"
#include "cryptohome/challenge_credentials/challenge_credentials_test_utils.h"
#include "cryptohome/challenge_credentials/signature_sealing_test_utils.h"
#include "cryptohome/flatbuffer_schemas/structures.h"
#include "cryptohome/mock_key_challenge_service.h"

using brillo::Blob;
using brillo::BlobToString;
using brillo::CombineBlobs;
using brillo::SecureBlob;
using hwsec::TPMError;
using hwsec::TPMErrorBase;
using hwsec::TPMRetryAction;
using hwsec_foundation::Sha256;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::AnyNumber;
using testing::DoAll;
using testing::NiceMock;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;
using testing::Values;

namespace cryptohome {

namespace {

using HwsecAlgorithm = hwsec::CryptohomeFrontend::SignatureSealingAlgorithm;

HwsecAlgorithm ConvertAlgorithm(
    structure::ChallengeSignatureAlgorithm algorithm) {
  switch (algorithm) {
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1:
      return HwsecAlgorithm::kRsassaPkcs1V15Sha1;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256:
      return HwsecAlgorithm::kRsassaPkcs1V15Sha256;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha384:
      return HwsecAlgorithm::kRsassaPkcs1V15Sha384;
    case structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha512:
      return HwsecAlgorithm::kRsassaPkcs1V15Sha512;
  }
  NOTREACHED();
  return static_cast<HwsecAlgorithm>(algorithm);
}

structure::ChallengePublicKeyInfo MakeChallengePublicKeyInfo(
    const Blob& set_public_key_spki_der,
    const std::vector<structure::ChallengeSignatureAlgorithm>& key_algorithms) {
  structure::ChallengePublicKeyInfo public_key_info;
  public_key_info.public_key_spki_der = set_public_key_spki_der;
  for (auto key_algorithm : key_algorithms)
    public_key_info.signature_algorithm.push_back(key_algorithm);
  return public_key_info;
}

structure::SignatureChallengeInfo MakeFakeKeysetChallengeInfo(
    const Blob& public_key_spki_der,
    const Blob& salt,
    structure::ChallengeSignatureAlgorithm salt_challenge_algorithm) {
  structure::SignatureChallengeInfo keyset_challenge_info;
  keyset_challenge_info.public_key_spki_der = public_key_spki_der;
  keyset_challenge_info.sealed_secret =
      MakeFakeSignatureSealedData(public_key_spki_der);
  keyset_challenge_info.salt = salt;
  keyset_challenge_info.salt_signature_algorithm = salt_challenge_algorithm;
  return keyset_challenge_info;
}

// Base fixture class that provides some common constants, helpers and mocks for
// testing ChallengeCredentialsHelperImpl.
class ChallengeCredentialsHelperImplTestBase : public testing::Test {
 public:
  void SetUp() override {
    ON_CALL(hwsec_, IsReady()).WillByDefault(ReturnValue(true));
    ON_CALL(hwsec_, IsSrkRocaVulnerable()).WillByDefault(ReturnValue(false));
  }

 protected:
  ChallengeCredentialsHelperImplTestBase()
      : challenge_credentials_helper_(&hwsec_) {}

  // Starts the asynchronous GenerateNew() operation.  The result, once the
  // operation completes, will be stored in |generate_new_result|.
  void CallGenerateNew(
      const std::vector<structure::ChallengeSignatureAlgorithm>& key_algorithms,
      std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>*
          generate_new_result) {
    DCHECK(challenge_service_);
    const structure::ChallengePublicKeyInfo public_key_info =
        MakeChallengePublicKeyInfo(kPublicKeySpkiDer, key_algorithms);
    challenge_credentials_helper_.GenerateNew(
        kUserEmail, public_key_info, kObfuscatedUsername,
        std::move(challenge_service_),
        MakeChallengeCredentialsGenerateNewResultWriter(generate_new_result));
  }

  // Starts the asynchronous Decrypt() operation.  The result, once the
  // operation completes, will be stored in |decrypt_result|.
  void CallDecrypt(
      const std::vector<structure::ChallengeSignatureAlgorithm>& key_algorithms,
      structure::ChallengeSignatureAlgorithm salt_challenge_algorithm,
      const Blob& salt,
      std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>*
          decrypt_result) {
    DCHECK(challenge_service_);
    const structure::ChallengePublicKeyInfo public_key_info =
        MakeChallengePublicKeyInfo(kPublicKeySpkiDer, key_algorithms);
    const structure::SignatureChallengeInfo keyset_challenge_info =
        MakeFakeKeysetChallengeInfo(kPublicKeySpkiDer, salt,
                                    salt_challenge_algorithm);
    challenge_credentials_helper_.Decrypt(
        kUserEmail, public_key_info, keyset_challenge_info,
        std::move(challenge_service_),
        MakeChallengeCredentialsDecryptResultWriter(decrypt_result));
  }

  // Starts the Decrypt() operation without observing the challenge requests it
  // makes or its result. Intended to be used for testing the corner case of
  // starting an operation before the previous one is completed.
  void StartSurplusOperation() {
    // Use different parameters here, to avoid clashing with mocks set up for
    // the normal operation.
    constexpr structure::ChallengeSignatureAlgorithm kLocalAlgorithm =
        structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256;
    const Blob kLocalPublicKeySpkiDer =
        CombineBlobs({kPublicKeySpkiDer, Blob(1)});

    auto unsealing_mocker =
        MakeUnsealingMocker({kLocalAlgorithm} /* key_algorithms */,
                            kLocalAlgorithm /* unsealing_algorithm */);
    unsealing_mocker->set_public_key_spki_der(kLocalPublicKeySpkiDer);
    unsealing_mocker->SetUpUnsealingNotCalledMock();

    auto mock_key_challenge_service =
        std::make_unique<MockKeyChallengeService>();
    EXPECT_CALL(*mock_key_challenge_service, ChallengeKeyMovable(_, _, _))
        .Times(AnyNumber());
    const structure::ChallengePublicKeyInfo public_key_info =
        MakeChallengePublicKeyInfo(kLocalPublicKeySpkiDer,
                                   {kLocalAlgorithm} /* key_algorithms */);
    const structure::SignatureChallengeInfo keyset_challenge_info =
        MakeFakeKeysetChallengeInfo(
            kLocalPublicKeySpkiDer, kSalt,
            kLocalAlgorithm /* salt_challenge_algorithm */);
    challenge_credentials_helper_.Decrypt(
        kUserEmail, public_key_info, keyset_challenge_info,
        std::move(mock_key_challenge_service), base::DoNothing());
  }

  // Assert that the given GenerateNew() operation result is a valid success
  // result.
  void VerifySuccessfulGenerateNewResult(
      const ChallengeCredentialsHelper::GenerateNewOrDecryptResult&
          generate_new_result) const {
    VerifySuccessfulChallengeCredentialsGenerateNewResult(generate_new_result,
                                                          kPasskey);
  }

  // Assert that the given Decrypt() operation result is a valid success result.
  void VerifySuccessfulDecryptResult(
      const ChallengeCredentialsHelper::GenerateNewOrDecryptResult&
          decrypt_result) const {
    VerifySuccessfulChallengeCredentialsDecryptResult(decrypt_result, kPasskey);
  }

  // Returns a helper object that aids mocking of the sealed secret creation
  // functionality.
  std::unique_ptr<SignatureSealedCreationMocker> MakeSealedCreationMocker(
      const std::vector<structure::ChallengeSignatureAlgorithm>&
          key_algorithms) {
    EXPECT_CALL(hwsec_, GetRandomSecureBlob(_))
        .WillOnce(ReturnValue(kTpmProtectedSecret));

    std::vector<HwsecAlgorithm> hwsec_key_algorithms;
    for (auto algo : key_algorithms) {
      hwsec_key_algorithms.push_back(ConvertAlgorithm(algo));
    }
    auto mocker = std::make_unique<SignatureSealedCreationMocker>(&hwsec_);
    mocker->set_public_key_spki_der(kPublicKeySpkiDer);
    mocker->set_key_algorithms(hwsec_key_algorithms);
    mocker->set_obfuscated_username(kObfuscatedUsername);
    mocker->set_secret_value(kTpmProtectedSecret);
    return mocker;
  }

  // Returns a helper object that aids mocking of the secret unsealing
  // functionality.
  std::unique_ptr<SignatureSealedUnsealingMocker> MakeUnsealingMocker(
      const std::vector<structure::ChallengeSignatureAlgorithm>& key_algorithms,
      structure::ChallengeSignatureAlgorithm unsealing_algorithm) {
    std::vector<HwsecAlgorithm> hwsec_key_algorithms;
    for (auto algo : key_algorithms) {
      hwsec_key_algorithms.push_back(ConvertAlgorithm(algo));
    }
    auto mocker = std::make_unique<SignatureSealedUnsealingMocker>(&hwsec_);
    mocker->set_public_key_spki_der(kPublicKeySpkiDer);
    mocker->set_key_algorithms(hwsec_key_algorithms);
    mocker->set_chosen_algorithm(ConvertAlgorithm(unsealing_algorithm));
    mocker->set_challenge_value(kUnsealingChallengeValue);
    mocker->set_challenge_signature(kUnsealingChallengeSignature);
    mocker->set_secret_value(kTpmProtectedSecret);
    return mocker;
  }

  // Sets up an expectation that the salt challenge request will be issued via
  // |challenge_service_|.
  void ExpectSaltChallenge(
      structure::ChallengeSignatureAlgorithm salt_challenge_algorithm) {
    salt_challenge_mock_controller_.ExpectSignatureChallenge(
        kUserEmail, kPublicKeySpkiDer, kSalt, salt_challenge_algorithm);
  }

  // Whether the salt challenge request has been started.
  bool is_salt_challenge_requested() const {
    return salt_challenge_mock_controller_.is_challenge_requested();
  }

  // Injects a simulated successful response for the currently running salt
  // challenge request.
  void SimulateSaltChallengeResponse() {
    salt_challenge_mock_controller_.SimulateSignatureChallengeResponse(
        kSaltSignature);
  }

  // Injects a simulated failure response for the currently running salt
  // challenge request.
  void SimulateSaltChallengeFailure() {
    salt_challenge_mock_controller_.SimulateFailureResponse();
  }

  // Sets up an expectation that the secret unsealing challenge request will be
  // issued via |challenge_service_|.
  void ExpectUnsealingChallenge(
      structure::ChallengeSignatureAlgorithm unsealing_algorithm) {
    unsealing_challenge_mock_controller_.ExpectSignatureChallenge(
        kUserEmail, kPublicKeySpkiDer, kUnsealingChallengeValue,
        unsealing_algorithm);
  }

  // Whether the secret unsealing challenge request has been started.
  bool is_unsealing_challenge_requested() const {
    return unsealing_challenge_mock_controller_.is_challenge_requested();
  }

  // Injects a simulated successful response for the currently running secret
  // unsealing challenge request.
  void SimulateUnsealingChallengeResponse() {
    unsealing_challenge_mock_controller_.SimulateSignatureChallengeResponse(
        kUnsealingChallengeSignature);
  }

  // Injects a simulated failure response for the currently running secret
  // unsealing challenge request.
  void SimulateUnsealingChallengeFailure() {
    unsealing_challenge_mock_controller_.SimulateFailureResponse();
  }

  // Sets up a mock for the successful salt generation.
  void SetSuccessfulSaltGenerationMock() {
    EXPECT_CALL(hwsec_, GetRandomBlob(kChallengeCredentialsSaltRandomByteCount))
        .WillOnce(ReturnValue(kSaltRandomPart));
  }

  // Sets up a mock for the failure during salt generation.
  void SetFailingSaltGenerationMock() {
    EXPECT_CALL(hwsec_, GetRandomBlob(kChallengeCredentialsSaltRandomByteCount))
        .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  }

  // Sets up a mock for vulnerable SRK.
  void SetVulnerableSrk() {
    EXPECT_CALL(hwsec_, IsSrkRocaVulnerable).WillOnce(ReturnValue(true));
  }

  // Sets up a mock for unavailable TPM.
  void SetUnavailableTpm() {
    EXPECT_CALL(hwsec_, IsReady).WillOnce(ReturnValue(false));
  }

  // Sets up a mock for when we can't check if SRK is vulnerable.
  void SetSrkVulnerabilityUnknown() {
    EXPECT_CALL(hwsec_, IsSrkRocaVulnerable)
        .WillRepeatedly(
            ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  }

  // Sets up a mock for when we can't check if SRK is vulnerable.
  void SetTpmAvailabilityUnknown() {
    EXPECT_CALL(hwsec_, IsReady)
        .WillRepeatedly(
            ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
  }

 protected:
  // Constants which are passed as fake data inputs to the
  // ChallengeCredentialsHelperImpl methods:

  // Fake user e-mail. It's supplied to the ChallengeCredentialsHelperImpl
  // operation methods. Then it's verified to be passed alongside challenge
  // requests made via KeyChallengeService, and to be present in the resulting
  // Credentials.
  const Username kUserEmail{"foo@example.com"};
  // Fake Subject Public Key Information of the challenged cryptographic key.
  // It's supplied to the ChallengeCredentialsHelperImpl operation methods as a
  // field of both |key_data| and |keyset_challenge_info| parameters. Then it's
  // verified to be passed into SignatureSealing methods and to be used
  // for challenge requests made via KeyChallengeService.
  const Blob kPublicKeySpkiDer{{3, 3, 3}};
  // Fake random part of the salt. When testing the GenerateNew() operation,
  // it's injected as a fake result of the TPM GetRandomDataBlob(). It's also
  // used as part of the |kSalt| constant in a few other places.
  const Blob kSaltRandomPart = Blob(20, 4);
  // Fake salt value. It's supplied to the ChallengeCredentialsHelperImpl
  // operation methods as a field of the |keyset_challenge_info| parameter. Then
  // it's verified to be used as the challenge value for one of requests made
  // via KeyChallengeService.
  const Blob kSalt = CombineBlobs(
      {GetChallengeCredentialsSaltConstantPrefix(), kSaltRandomPart});
  // Fake obfuscated username: It's supplied to the GenerateNew() operation.
  // Then it's verified to be passed into the
  // hwsec::CryptohomeFrontend::SealWithSignatureAndCurrentUser method.
  const ObfuscatedUsername kObfuscatedUsername{"obfuscated_username"};
  // Fake PCR restrictions.
  const std::map<uint32_t, brillo::Blob> kDefaultPcrMap{{0, {9, 9, 9}},
                                                        {10, {11, 11, 11}}};
  const std::map<uint32_t, brillo::Blob> kExtendedPcrMap{{0, {9, 9, 9}},
                                                         {10, {12, 12, 12}}};

  // Constants which are injected as fake data into intermediate steps of the
  // ChallengeCredentialsHelperImpl operations:

  // Fake signature of |kSalt| using the |salt_challenge_algorithm_| algorithm.
  // It's injected as a fake response to the salt challenge request made via
  // KeyChallengeService. Then it's implicitly verified to be used for the
  // generation of the passkey in the resulting Credentials - see the |kPasskey|
  // constant.
  const Blob kSaltSignature{{5, 5, 5}};
  // Fake challenge value for unsealing the secret. It's injected as a fake
  // value returned from
  // hwsec::CryptohomeFrontend::ChallengeWithSignatureAndCurrentUser(). Then
  // it's verified to be used as the challenge value for one of requests made
  // via KeyChallengeService.
  const Blob kUnsealingChallengeValue{{6, 6, 6}};
  // Fake signature of |kUnsealingChallengeValue| using the
  // |unsealing_algorithm_| algorithm. It's injected as a fake response to the
  // unsealing challenge request made via KeyChallengeService. Then it's
  // verified to be passed to the Unseal() method of
  // hwsec::CryptohomeFrontend::ChallengeWithSignatureAndCurrentUser.
  const Blob kUnsealingChallengeSignature{{7, 7, 7}};
  // Fake TPM-protected secret. When testing the GenerateNew() operation, it's
  // injected as a fake result of
  // hwsec::CryptohomeFrontend::SealWithSignatureAndCurrentUser() method. When
  // testing the Decrypt() operation, it's injected as a fake result of the
  // Unseal() method of
  // hwsec::CryptohomeFrontend::ChallengeWithSignatureAndCurrentUser(). Also
  // this constant is implicitly verified to be used for the generation of the
  // passkey in the resulting Credentials - see the |kPasskey| constant.
  const SecureBlob kTpmProtectedSecret{{8, 8, 8}};

  // The expected passkey of the resulting Credentials returned from the
  // ChallengeCredentialsHelperImpl operations. Its value is derived from the
  // injected fake data.
  const SecureBlob kPasskey = SecureBlob::Combine(
      kTpmProtectedSecret, SecureBlob(Sha256(kSaltSignature)));

 private:
  // Mock objects:

  NiceMock<hwsec::MockCryptohomeFrontend> hwsec_;
  std::unique_ptr<StrictMock<MockKeyChallengeService>> challenge_service_ =
      std::make_unique<StrictMock<MockKeyChallengeService>>();
  KeyChallengeServiceMockController salt_challenge_mock_controller_{
      challenge_service_.get()};
  KeyChallengeServiceMockController unsealing_challenge_mock_controller_{
      challenge_service_.get()};

  // The tested instance.
  ChallengeCredentialsHelperImpl challenge_credentials_helper_;
};

// Base fixture class that uses a single algorithm and have the sealing backend
// available.
class ChallengeCredentialsHelperImplBasicTest
    : public ChallengeCredentialsHelperImplTestBase {
 protected:
  // The single algorithm to be used in this test.
  static constexpr structure::ChallengeSignatureAlgorithm kAlgorithm =
      structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256;

  ChallengeCredentialsHelperImplBasicTest() {}
};

}  // namespace

// Test success of the GenerateNew() operation.
TEST_F(ChallengeCredentialsHelperImplBasicTest, GenerateNewSuccess) {
  SetSuccessfulSaltGenerationMock();
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  MakeSealedCreationMocker({kAlgorithm} /* key_algorithms */)
      ->SetUpSuccessfulMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      generate_new_result;
  CallGenerateNew({kAlgorithm} /* key_algorithms */, &generate_new_result);
  EXPECT_FALSE(generate_new_result);
  EXPECT_TRUE(is_salt_challenge_requested());

  SimulateSaltChallengeResponse();
  ASSERT_TRUE(generate_new_result);
  VerifySuccessfulGenerateNewResult(*generate_new_result);
}

// Test failure of the GenerateNew() operation due to SRK vulnerable to ROCA.
TEST_F(ChallengeCredentialsHelperImplBasicTest, GenerateNewFailureInROCA) {
  SetVulnerableSrk();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      generate_new_result;
  CallGenerateNew({kAlgorithm} /* key_algorithms */, &generate_new_result);
  ASSERT_FALSE(generate_new_result);
}

// Test failure of the GenerateNew() operation due to SRK vulnerable to ROCA.
TEST_F(ChallengeCredentialsHelperImplBasicTest, GenerateNewFailureInTpm) {
  SetUnavailableTpm();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      generate_new_result;
  CallGenerateNew({kAlgorithm} /* key_algorithms */, &generate_new_result);
  ASSERT_FALSE(generate_new_result);
}

// Test failure of the GenerateNew() operation due to failure to query SRK ROCA
// status.
TEST_F(ChallengeCredentialsHelperImplBasicTest, GenerateNewFailureInROCACheck) {
  SetSrkVulnerabilityUnknown();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      generate_new_result;
  CallGenerateNew({kAlgorithm} /* key_algorithms */, &generate_new_result);
  ASSERT_FALSE(generate_new_result);
}

// Test failure of the GenerateNew() operation due to failure to query SRK ROCA
// status.
TEST_F(ChallengeCredentialsHelperImplBasicTest, GenerateNewFailureInTpmCheck) {
  SetTpmAvailabilityUnknown();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      generate_new_result;
  CallGenerateNew({kAlgorithm} /* key_algorithms */, &generate_new_result);
  ASSERT_FALSE(generate_new_result);
}

// Test failure of the GenerateNew() operation due to failure in salt
// generation.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       GenerateNewFailureInSaltGeneration) {
  SetFailingSaltGenerationMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      generate_new_result;
  CallGenerateNew({kAlgorithm} /* key_algorithms */, &generate_new_result);
  ASSERT_FALSE(generate_new_result);
}

// Test failure of the GenerateNew() operation due to failure of salt challenge
// request.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       GenerateNewFailureInSaltChallenge) {
  SetSuccessfulSaltGenerationMock();
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  MakeSealedCreationMocker({kAlgorithm} /* key_algorithms */)
      ->SetUpSuccessfulMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      generate_new_result;
  CallGenerateNew({kAlgorithm} /* key_algorithms */, &generate_new_result);
  EXPECT_FALSE(generate_new_result);
  EXPECT_TRUE(is_salt_challenge_requested());

  SimulateSaltChallengeFailure();
  ASSERT_FALSE(generate_new_result);
}

// Test failure of the GenerateNew() operation due to failure of sealed secret
// creation.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       GenerateNewFailureInSealedCreation) {
  SetSuccessfulSaltGenerationMock();
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  MakeSealedCreationMocker({kAlgorithm} /* key_algorithms */)
      ->SetUpFailingMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      generate_new_result;
  CallGenerateNew({kAlgorithm} /* key_algorithms */, &generate_new_result);
  ASSERT_FALSE(generate_new_result);
}

// Test failure of the Decrypt() operation due to SRK vulnerable to ROCA.
TEST_F(ChallengeCredentialsHelperImplBasicTest, DecryptFailureInROCA) {
  SetVulnerableSrk();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, Blob() /* salt */,
              &decrypt_result);
  ASSERT_FALSE(decrypt_result);
}

// Test failure of the Decrypt() operation due to SRK vulnerable to ROCA.
TEST_F(ChallengeCredentialsHelperImplBasicTest, DecryptFailureInTpm) {
  SetUnavailableTpm();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, Blob() /* salt */,
              &decrypt_result);
  ASSERT_FALSE(decrypt_result);
}

// Test failure of the Decrypt() operation due to failure to query SRK ROCA
// status.
TEST_F(ChallengeCredentialsHelperImplBasicTest, DecryptFailureInROCACheck) {
  SetSrkVulnerabilityUnknown();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, Blob() /* salt */,
              &decrypt_result);
  ASSERT_FALSE(decrypt_result);
}

// Test failure of the Decrypt() operation due to failure to query SRK ROCA
// status.
TEST_F(ChallengeCredentialsHelperImplBasicTest, DecryptFailureInTpmCheck) {
  SetTpmAvailabilityUnknown();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, Blob() /* salt */,
              &decrypt_result);
  ASSERT_FALSE(decrypt_result);
}

// Test failure of the Decrypt() operation due to the input salt being empty.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       DecryptFailureInSaltCheckEmpty) {
  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, Blob() /* salt */,
              &decrypt_result);
  ASSERT_FALSE(decrypt_result);
}

// Test failure of the Decrypt() operation due to the input salt not starting
// with the expected constant prefix.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       DecryptFailureInSaltCheckNotPrefixed) {
  Blob salt = kSalt;
  salt[GetChallengeCredentialsSaltConstantPrefix().size() - 1] ^= 1;
  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, salt, &decrypt_result);
  ASSERT_FALSE(decrypt_result);
}

// Test failure of the Decrypt() operation due to the input salt containing
// nothing besides the expected constant prefix.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       DecryptFailureInSaltCheckNothingBesidesPrefix) {
  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */,
              GetChallengeCredentialsSaltConstantPrefix() /* salt */,
              &decrypt_result);
  ASSERT_FALSE(decrypt_result);
}

// Test success of the Decrypt() operation in scenario when the salt challenge
// response comes before the unsealing challenge response.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       DecryptSuccessSaltThenUnsealing) {
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  ExpectUnsealingChallenge(kAlgorithm /* unsealing_algorithm */);
  MakeUnsealingMocker({kAlgorithm} /* key_algorithms */,
                      kAlgorithm /* unsealing_algorithm */)
      ->SetUpSuccessfulMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, kSalt,
              &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());
  EXPECT_TRUE(is_unsealing_challenge_requested());

  SimulateSaltChallengeResponse();
  EXPECT_FALSE(decrypt_result);

  SimulateUnsealingChallengeResponse();
  ASSERT_TRUE(decrypt_result);
  VerifySuccessfulDecryptResult(*decrypt_result);
}

// Test success of the Decrypt() operation in scenario when the unsealing
// challenge response comes before the salt challenge response.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       DecryptSuccessUnsealingThenSalt) {
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  ExpectUnsealingChallenge(kAlgorithm /* unsealing_algorithm */);
  MakeUnsealingMocker({kAlgorithm} /* key_algorithms */,
                      kAlgorithm /* unsealing_algorithm */)
      ->SetUpSuccessfulMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, kSalt,
              &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());
  EXPECT_TRUE(is_unsealing_challenge_requested());

  SimulateUnsealingChallengeResponse();
  EXPECT_FALSE(decrypt_result);

  SimulateSaltChallengeResponse();
  ASSERT_TRUE(decrypt_result);
  VerifySuccessfulDecryptResult(*decrypt_result);
}

// Test failure of the Decrypt() operation due to failure of unsealing session
// creation.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       DecryptFailureInUnsealingSessionCreation) {
  for (int attempt_number = 0;
       attempt_number < ChallengeCredentialsHelperImpl::kRetryAttemptCount;
       ++attempt_number) {
    ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  }
  MakeUnsealingMocker({kAlgorithm} /* key_algorithms */,
                      kAlgorithm /* unsealing_algorithm */)
      ->SetUpCreationFailingMock(true /* mock_repeatedly */);

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, kSalt,
              &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());
  ASSERT_FALSE(decrypt_result);

  // Responding to the salt challenge shouldn't have any effect.
  SimulateSaltChallengeResponse();
}

// Test failure of the Decrypt() operation due to failure of unsealing.
TEST_F(ChallengeCredentialsHelperImplBasicTest, DecryptFailureInUnsealing) {
  for (int attempt_number = 0;
       attempt_number < ChallengeCredentialsHelperImpl::kRetryAttemptCount;
       ++attempt_number) {
    ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
    ExpectUnsealingChallenge(kAlgorithm /* unsealing_algorithm */);
    MakeUnsealingMocker({kAlgorithm} /* key_algorithms */,
                        kAlgorithm /* unsealing_algorithm */)
        ->SetUpUsealingFailingMock();
  }

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, kSalt,
              &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());

  for (int attempt_number = 0;
       attempt_number < ChallengeCredentialsHelperImpl::kRetryAttemptCount;
       ++attempt_number) {
    EXPECT_TRUE(is_unsealing_challenge_requested());
    EXPECT_FALSE(decrypt_result);
    SimulateUnsealingChallengeResponse();
  }
  ASSERT_FALSE(decrypt_result);

  // Responding to the salt challenge shouldn't have any effect.
  SimulateSaltChallengeResponse();
}

// Test failure of the Decrypt() operation due to failure of salt challenge
// request.
TEST_F(ChallengeCredentialsHelperImplBasicTest, DecryptFailureInSaltChallenge) {
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  ExpectUnsealingChallenge(kAlgorithm /* unsealing_algorithm */);
  MakeUnsealingMocker({kAlgorithm} /* key_algorithms */,
                      kAlgorithm /* unsealing_algorithm */)
      ->SetUpUnsealingNotCalledMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, kSalt,
              &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());
  EXPECT_TRUE(is_unsealing_challenge_requested());
  EXPECT_FALSE(decrypt_result);

  SimulateSaltChallengeFailure();
  ASSERT_FALSE(decrypt_result);

  // Responding to the unsealing challenge shouldn't have any effect.
  SimulateUnsealingChallengeResponse();
}

// Test failure of the Decrypt() operation due to failure of unsealing challenge
// request.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       DecryptFailureInUnsealingChallenge) {
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  ExpectUnsealingChallenge(kAlgorithm /* unsealing_algorithm */);
  MakeUnsealingMocker({kAlgorithm} /* key_algorithms */,
                      kAlgorithm /* unsealing_algorithm */)
      ->SetUpUnsealingNotCalledMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, kSalt,
              &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());
  EXPECT_TRUE(is_unsealing_challenge_requested());
  EXPECT_FALSE(decrypt_result);

  SimulateUnsealingChallengeFailure();
  ASSERT_FALSE(decrypt_result);

  // Responding to the salt challenge shouldn't have any effect.
  SimulateSaltChallengeResponse();
}

// Test failure of the Decrypt() operation due to its abortion before any of the
// challenges is completed.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       DecryptAbortionBeforeChallenges) {
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  ExpectUnsealingChallenge(kAlgorithm /* unsealing_algorithm */);
  MakeUnsealingMocker({kAlgorithm} /* key_algorithms */,
                      kAlgorithm /* unsealing_algorithm */)
      ->SetUpUnsealingNotCalledMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, kSalt,
              &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());
  EXPECT_TRUE(is_unsealing_challenge_requested());
  EXPECT_FALSE(decrypt_result);

  // Abort the first operation by starting a new one.
  StartSurplusOperation();
  ASSERT_FALSE(decrypt_result);
}

// Test failure of the Decrypt() operation due to its abortion after the salt
// challenge completes.
TEST_F(ChallengeCredentialsHelperImplBasicTest,
       DecryptAbortionAfterSaltChallenge) {
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  ExpectUnsealingChallenge(kAlgorithm /* unsealing_algorithm */);
  MakeUnsealingMocker({kAlgorithm} /* key_algorithms */,
                      kAlgorithm /* unsealing_algorithm */)
      ->SetUpUnsealingNotCalledMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, kSalt,
              &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());
  EXPECT_TRUE(is_unsealing_challenge_requested());

  SimulateSaltChallengeResponse();
  EXPECT_FALSE(decrypt_result);

  // Abort the first operation by starting a new one.
  StartSurplusOperation();
  ASSERT_FALSE(decrypt_result);
}

// Test failure of the Decrypt() operation due to its abortion after the
// unsealing completes.
TEST_F(ChallengeCredentialsHelperImplBasicTest, DecryptAbortionAfterUnsealing) {
  ExpectSaltChallenge(kAlgorithm /* salt_challenge_algorithm */);
  ExpectUnsealingChallenge(kAlgorithm /* unsealing_algorithm */);
  MakeUnsealingMocker({kAlgorithm} /* key_algorithms */,
                      kAlgorithm /* unsealing_algorithm */)
      ->SetUpSuccessfulMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt({kAlgorithm} /* key_algorithms */,
              kAlgorithm /* salt_challenge_algorithm */, kSalt,
              &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());
  EXPECT_TRUE(is_unsealing_challenge_requested());

  SimulateUnsealingChallengeResponse();
  EXPECT_FALSE(decrypt_result);

  // Abort the first operation by starting a new one.
  StartSurplusOperation();
  ASSERT_FALSE(decrypt_result);
}

namespace {

// Test parameters for ChallengeCredentialsHelperImplAlgorithmsTest.
struct AlgorithmsTestParam {
  std::vector<structure::ChallengeSignatureAlgorithm> key_algorithms;
  structure::ChallengeSignatureAlgorithm salt_challenge_algorithm;
  structure::ChallengeSignatureAlgorithm unsealing_algorithm;
};

// Tests various combinations of multiple algorithms.
class ChallengeCredentialsHelperImplAlgorithmsTest
    : public ChallengeCredentialsHelperImplTestBase,
      public testing::WithParamInterface<AlgorithmsTestParam> {
 protected:
  ChallengeCredentialsHelperImplAlgorithmsTest() = default;
};

}  // namespace

// Test success of the Decrypt() operation with the specified combination of
// algorithms.
TEST_P(ChallengeCredentialsHelperImplAlgorithmsTest, DecryptSuccess) {
  ExpectSaltChallenge(GetParam().salt_challenge_algorithm);
  ExpectUnsealingChallenge(GetParam().unsealing_algorithm);
  MakeUnsealingMocker(GetParam().key_algorithms, GetParam().unsealing_algorithm)
      ->SetUpSuccessfulMock();

  std::unique_ptr<ChallengeCredentialsHelper::GenerateNewOrDecryptResult>
      decrypt_result;
  CallDecrypt(GetParam().key_algorithms, GetParam().salt_challenge_algorithm,
              kSalt, &decrypt_result);
  EXPECT_TRUE(is_salt_challenge_requested());
  EXPECT_TRUE(is_unsealing_challenge_requested());

  SimulateSaltChallengeResponse();
  EXPECT_FALSE(decrypt_result);

  SimulateUnsealingChallengeResponse();
  ASSERT_TRUE(decrypt_result);
  VerifySuccessfulDecryptResult(*decrypt_result);
}

// Test that SHA-1 algorithms are the least preferred and chosen only if there's
// no other option.
INSTANTIATE_TEST_SUITE_P(
    LowPriorityOfSha1,
    ChallengeCredentialsHelperImplAlgorithmsTest,
    Values(
        AlgorithmsTestParam{
            {structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha1,
             structure::ChallengeSignatureAlgorithm::
                 kRsassaPkcs1V15Sha256} /* key_algorithms */,
            structure::ChallengeSignatureAlgorithm::
                kRsassaPkcs1V15Sha256 /* salt_challenge_algorithm */,
            structure::ChallengeSignatureAlgorithm::
                kRsassaPkcs1V15Sha256 /* unsealing_algorithm */},
        AlgorithmsTestParam{
            {structure::ChallengeSignatureAlgorithm::
                 kRsassaPkcs1V15Sha1} /* key_algorithms */,
            structure::ChallengeSignatureAlgorithm::
                kRsassaPkcs1V15Sha1 /* salt_challenge_algorithm */,
            structure::ChallengeSignatureAlgorithm::
                kRsassaPkcs1V15Sha1 /* unsealing_algorithm */}));

// Test prioritization of algorithms according to their order in the input.
INSTANTIATE_TEST_SUITE_P(
    InputPrioritization,
    ChallengeCredentialsHelperImplAlgorithmsTest,
    Values(
        AlgorithmsTestParam{
            {structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha256,
             structure::ChallengeSignatureAlgorithm::
                 kRsassaPkcs1V15Sha512} /* key_algorithms */,
            structure::ChallengeSignatureAlgorithm::
                kRsassaPkcs1V15Sha256 /* salt_challenge_algorithm */,
            structure::ChallengeSignatureAlgorithm::
                kRsassaPkcs1V15Sha256 /* unsealing_algorithm */},
        AlgorithmsTestParam{
            {structure::ChallengeSignatureAlgorithm::kRsassaPkcs1V15Sha512,
             structure::ChallengeSignatureAlgorithm::
                 kRsassaPkcs1V15Sha256} /* key_algorithms */,
            structure::ChallengeSignatureAlgorithm::
                kRsassaPkcs1V15Sha512 /* salt_challenge_algorithm */,
            structure::ChallengeSignatureAlgorithm::
                kRsassaPkcs1V15Sha512 /* unsealing_algorithm */}));

}  // namespace cryptohome
