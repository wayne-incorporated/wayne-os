// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_CHALLENGE_CREDENTIALS_SIGNATURE_SEALING_TEST_UTILS_H_
#define CRYPTOHOME_CHALLENGE_CREDENTIALS_SIGNATURE_SEALING_TEST_UTILS_H_

#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include <brillo/secure_blob.h>
#include <libhwsec/frontend/cryptohome/mock_frontend.h>

#include "cryptohome/flatbuffer_schemas/structures.h"
#include "cryptohome/username.h"

namespace cryptohome {

// Creates the SignatureSealedData protobuf message filled with some fake
// values.
hwsec::SignatureSealedData MakeFakeSignatureSealedData(
    const brillo::Blob& public_key_spki_der);

// Helper for setting up mock expectation and mock response for the
// signature-sealed secret creation functionality
//
// This class follows the "builder" pattern - i.e., first use the set_*()
// methods to set up expected parameters, and then call one of the SetUp*Mock()
// methods to actually set up the mock expectation with the desired behavior.
class SignatureSealedCreationMocker final {
 public:
  explicit SignatureSealedCreationMocker(
      hwsec::MockCryptohomeFrontend* mock_hwsec);
  SignatureSealedCreationMocker(const SignatureSealedCreationMocker&) = delete;
  SignatureSealedCreationMocker& operator=(
      const SignatureSealedCreationMocker&) = delete;

  ~SignatureSealedCreationMocker();

  void set_public_key_spki_der(const brillo::Blob& public_key_spki_der) {
    public_key_spki_der_ = public_key_spki_der;
  }
  void set_key_algorithms(
      const std::vector<hwsec::CryptohomeFrontend::SignatureSealingAlgorithm>&
          key_algorithms) {
    key_algorithms_ = key_algorithms;
  }
  void set_obfuscated_username(const ObfuscatedUsername& obfuscated_username) {
    obfuscated_username_ = obfuscated_username;
  }
  void set_secret_value(const brillo::SecureBlob& secret_value) {
    secret_value_ = secret_value;
  }

  // Sets up the CreateSealedSecret() mock that will report success and return a
  // fake result (see MakeFakeSignatureSealedData()).
  void SetUpSuccessfulMock();
  // Sets up the CreateSealedSecret() mock that will report failure.
  void SetUpFailingMock();

 private:
  hwsec::MockCryptohomeFrontend* const mock_hwsec_;
  brillo::Blob public_key_spki_der_;
  std::vector<hwsec::CryptohomeFrontend::SignatureSealingAlgorithm>
      key_algorithms_;
  ObfuscatedUsername obfuscated_username_;
  brillo::SecureBlob secret_value_;
};

// Helper for setting up mock expectation and mock response for the
// unsealing functionality of signature-sealed secret
//
// This class follows the "builder" pattern - i.e., first use the set_*()
// methods to set up expected parameters and values to be returned, and then
// call one of the SetUp*Mock() methods to actually set up the mock expectation
// with the desired behavior.
class SignatureSealedUnsealingMocker final {
 public:
  explicit SignatureSealedUnsealingMocker(
      hwsec::MockCryptohomeFrontend* mock_hwsec);
  SignatureSealedUnsealingMocker(const SignatureSealedUnsealingMocker&) =
      delete;
  SignatureSealedUnsealingMocker& operator=(
      const SignatureSealedUnsealingMocker&) = delete;

  ~SignatureSealedUnsealingMocker();

  void set_public_key_spki_der(const brillo::Blob& public_key_spki_der) {
    public_key_spki_der_ = public_key_spki_der;
  }
  void set_key_algorithms(
      const std::vector<hwsec::CryptohomeFrontend::SignatureSealingAlgorithm>&
          key_algorithms) {
    key_algorithms_ = key_algorithms;
  }
  void set_chosen_algorithm(
      hwsec::CryptohomeFrontend::SignatureSealingAlgorithm chosen_algorithm) {
    chosen_algorithm_ = chosen_algorithm;
  }
  void set_challenge_value(const brillo::Blob& challenge_value) {
    challenge_value_ = challenge_value;
  }
  void set_challenge_signature(const brillo::Blob& challenge_signature) {
    challenge_signature_ = challenge_signature;
  }
  void set_secret_value(const brillo::SecureBlob& secret_value) {
    secret_value_ = secret_value;
  }

  // Sets up mocks that will simulate the successful unsealing.
  void SetUpSuccessfulMock();
  // Sets up mocks that will report failure from
  // MockSignatureSealingBackend::CreateUnsealingSession().
  void SetUpCreationFailingMock(bool mock_repeatedly);
  // Sets up mocks that will report failure from
  // MockUnsealingSession::Unseal().
  void SetUpUsealingFailingMock();
  // Sets up mocks that report success from
  // MockSignatureSealingBackend::CreateUnsealingSession(), but with the
  // expectation that MockUnsealingSession::Unseal() is not called.
  void SetUpUnsealingNotCalledMock();

 private:
  void AddSessionCreationMock();

  hwsec::MockCryptohomeFrontend* const mock_hwsec_;
  brillo::Blob public_key_spki_der_;
  std::vector<hwsec::CryptohomeFrontend::SignatureSealingAlgorithm>
      key_algorithms_;
  hwsec::CryptohomeFrontend::SignatureSealingAlgorithm chosen_algorithm_ =
      hwsec::CryptohomeFrontend::SignatureSealingAlgorithm::kRsassaPkcs1V15Sha1;
  brillo::Blob challenge_value_;
  brillo::Blob challenge_signature_;
  brillo::SecureBlob secret_value_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_CHALLENGE_CREDENTIALS_SIGNATURE_SEALING_TEST_UTILS_H_
