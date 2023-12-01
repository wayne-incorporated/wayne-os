// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/challenge_credentials/signature_sealing_test_utils.h"

#include <memory>
#include <string>

#include <gmock/gmock.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>
#include <libhwsec/structures/signature_sealed_data_test_utils.h>
#include <libhwsec-foundation/error/testing_helper.h>

#include "cryptohome/flatbuffer_schemas/structures.h"

using brillo::Blob;
using brillo::BlobFromString;
using brillo::BlobToString;
using brillo::SecureBlob;
using hwsec::TPMError;
using hwsec::TPMErrorBase;
using hwsec::TPMRetryAction;
using hwsec_foundation::error::testing::ReturnError;
using hwsec_foundation::error::testing::ReturnValue;
using testing::_;
using testing::AtLeast;
using testing::ByMove;
using testing::DoAll;
using testing::Invoke;
using testing::Return;
using testing::SetArgPointee;
using testing::StrictMock;

namespace cryptohome {

hwsec::SignatureSealedData MakeFakeSignatureSealedData(
    const Blob& public_key_spki_der) {
  constexpr char kFakeTpm2SrkWrappedSecret[] = "ab";
  hwsec::SignatureSealedData sealed_data;
  // Fill some fields of the protobuf message just to make test/mock assertions
  // more meaningful. Note that it's unimportant that we use TPM2-specific
  // fields here.
  hwsec::Tpm2PolicySignedData sealed_data_contents;
  sealed_data_contents.public_key_spki_der = public_key_spki_der;
  sealed_data_contents.srk_wrapped_secret =
      BlobFromString(kFakeTpm2SrkWrappedSecret);
  sealed_data = sealed_data_contents;
  return sealed_data;
}

SignatureSealedCreationMocker::SignatureSealedCreationMocker(
    hwsec::MockCryptohomeFrontend* mock_hwsec)
    : mock_hwsec_(mock_hwsec) {}

SignatureSealedCreationMocker::~SignatureSealedCreationMocker() = default;

void SignatureSealedCreationMocker::SetUpSuccessfulMock() {
  const hwsec::SignatureSealedData sealed_data_to_return =
      MakeFakeSignatureSealedData(public_key_spki_der_);
  EXPECT_CALL(*mock_hwsec_, SealWithSignatureAndCurrentUser(
                                *obfuscated_username_, secret_value_,
                                public_key_spki_der_, key_algorithms_))
      .WillOnce(ReturnValue(sealed_data_to_return));
}

void SignatureSealedCreationMocker::SetUpFailingMock() {
  EXPECT_CALL(*mock_hwsec_, SealWithSignatureAndCurrentUser(
                                *obfuscated_username_, secret_value_,
                                public_key_spki_der_, key_algorithms_))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kNoRetry));
}

SignatureSealedUnsealingMocker::SignatureSealedUnsealingMocker(
    hwsec::MockCryptohomeFrontend* mock_hwsec)
    : mock_hwsec_(mock_hwsec) {}

SignatureSealedUnsealingMocker::~SignatureSealedUnsealingMocker() = default;

void SignatureSealedUnsealingMocker::SetUpSuccessfulMock() {
  AddSessionCreationMock();
  EXPECT_CALL(*mock_hwsec_, UnsealWithChallenge(_, challenge_signature_))
      .WillOnce(ReturnValue(secret_value_));
}

void SignatureSealedUnsealingMocker::SetUpCreationFailingMock(
    bool mock_repeatedly) {
  const hwsec::SignatureSealedData expected_sealed_data =
      MakeFakeSignatureSealedData(public_key_spki_der_);
  auto& expected_call = EXPECT_CALL(
      *mock_hwsec_,
      ChallengeWithSignatureAndCurrentUser(
          expected_sealed_data, public_key_spki_der_, key_algorithms_));
  if (mock_repeatedly)
    expected_call.WillRepeatedly(
        ReturnError<TPMError>("fake", TPMRetryAction::kLater));
  else
    expected_call.WillOnce(
        ReturnError<TPMError>("fake", TPMRetryAction::kLater));
}

void SignatureSealedUnsealingMocker::SetUpUsealingFailingMock() {
  AddSessionCreationMock();
  EXPECT_CALL(*mock_hwsec_, UnsealWithChallenge(_, challenge_signature_))
      .WillOnce(ReturnError<TPMError>("fake", TPMRetryAction::kLater))
      .RetiresOnSaturation();
}

void SignatureSealedUnsealingMocker::SetUpUnsealingNotCalledMock() {
  AddSessionCreationMock();
}

void SignatureSealedUnsealingMocker::AddSessionCreationMock() {
  const hwsec::SignatureSealedData expected_sealed_data =
      MakeFakeSignatureSealedData(public_key_spki_der_);
  EXPECT_CALL(*mock_hwsec_,
              ChallengeWithSignatureAndCurrentUser(
                  expected_sealed_data, public_key_spki_der_, key_algorithms_))
      .WillOnce(ReturnValue(hwsec::CryptohomeFrontend::ChallengeResult{
          .challenge_id =
              static_cast<hwsec::CryptohomeFrontend::ChallengeID>(123),
          .algorithm = chosen_algorithm_,
          .challenge = challenge_value_,
      }))
      .RetiresOnSaturation();
}

}  // namespace cryptohome
