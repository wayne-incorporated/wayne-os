// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_KEY_CHALLENGE_SERVICE_H_
#define CRYPTOHOME_MOCK_KEY_CHALLENGE_SERVICE_H_

#include <queue>
#include <string>

#include <base/functional/callback.h>
#include <brillo/secure_blob.h>
#include <cryptohome/proto_bindings/rpc.pb.h>
#include <gmock/gmock.h>

#include "cryptohome/flatbuffer_schemas/structures.h"
#include "cryptohome/key_challenge_service.h"
#include "cryptohome/username.h"

namespace cryptohome {

class MockKeyChallengeService : public KeyChallengeService {
 public:
  MockKeyChallengeService();
  ~MockKeyChallengeService() override;

  MOCK_METHOD(void,
              ChallengeKeyMovable,
              (const AccountIdentifier&,
               const KeyChallengeRequest&,
               ResponseCallback*));

  void ChallengeKey(const AccountIdentifier& account_id,
                    const KeyChallengeRequest& key_challenge_request,
                    ResponseCallback response_callback) override {
    // Note: this method contains a move-only argument and thus cannot be mocked
    // directly. Use ChallengeKeyMovable for all mocking needs.
    ChallengeKeyMovable(account_id, key_challenge_request, &response_callback);
  };

  MOCK_METHOD(void,
              FidoMakeCredentialMovable,
              (const std::string&,
               const cryptohome::fido::PublicKeyCredentialCreationOptions&,
               MakeCredentialCallback*));
  void FidoMakeCredential(
      const std::string& client_data_json,
      const cryptohome::fido::PublicKeyCredentialCreationOptions& options,
      MakeCredentialCallback response_callback) override {
    FidoMakeCredentialMovable(client_data_json, options, &response_callback);
  };

  MOCK_METHOD(void,
              FidoGetAssertionMovable,
              (const std::string&,
               const cryptohome::fido::PublicKeyCredentialRequestOptions&,
               GetAssertionCallback*));
  void FidoGetAssertion(
      const std::string& client_data,
      const cryptohome::fido::PublicKeyCredentialRequestOptions& request,
      GetAssertionCallback response_callback) override {
    FidoGetAssertionMovable(client_data, request, &response_callback);
  };
};

// Helper class for simplifying the use of MockKeyChallengeService.
//
// It encapsulates setting up a mock expectation and execution of the callback
// with which the mocked method was called. Intended usage: first call
// ExpectSignatureChallenge(), and then, after the mocked method gets executed,
// call one of the Simulate*() methods.
class KeyChallengeServiceMockController final {
 public:
  explicit KeyChallengeServiceMockController(
      MockKeyChallengeService* mock_service);
  ~KeyChallengeServiceMockController();

  // Sets up a mock expectation on ChallengeKey(). This mock expectation doesn't
  // run the passed ResponseCallback, but remembers it in
  // |intercepted_response_callback_|, allowing the later call of a Simulate*()
  // method.
  void ExpectSignatureChallenge(
      const Username& expected_username,
      const brillo::Blob& expected_public_key_spki_der,
      const brillo::Blob& expected_challenge_value,
      structure::ChallengeSignatureAlgorithm expected_signature_algorithm);

  // Whether the mocked ChallengeKey() has been called.
  //
  // It's allowed to call the Simulate*() methods only after this returns true.
  bool is_challenge_requested() const {
    return !intercepted_response_callbacks_.empty();
  }

  // Simulates a successful response for the given challenge request.
  void SimulateSignatureChallengeResponse(const brillo::Blob& signature_value);
  // Simulates a failed response for the given challenge request.
  void SimulateFailureResponse();

 private:
  // Not owned.
  MockKeyChallengeService* const mock_service_;
  // The accumulated response callbacks that was passed to the mocked
  // ChallengeKey() method.
  std::queue<KeyChallengeService::ResponseCallback>
      intercepted_response_callbacks_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_KEY_CHALLENGE_SERVICE_H_
