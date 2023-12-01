// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_AUTH_BLOCKS_FP_SERVICE_H_
#define CRYPTOHOME_AUTH_BLOCKS_FP_SERVICE_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <cryptohome/proto_bindings/UserDataAuth.pb.h>

#include "cryptohome/auth_blocks/prepare_token.h"
#include "cryptohome/credential_verifier.h"
#include "cryptohome/error/cryptohome_error.h"
#include "cryptohome/fingerprint_manager.h"
#include "cryptohome/util/async_init.h"

namespace cryptohome {

class FingerprintAuthBlockService {
 public:
  FingerprintAuthBlockService(
      AsyncInitPtr<FingerprintManager> fp_manager,
      base::RepeatingCallback<void(user_data_auth::FingerprintScanResult)>
          signal_sender);

  FingerprintAuthBlockService(const FingerprintAuthBlockService&) = delete;
  FingerprintAuthBlockService& operator=(const FingerprintAuthBlockService&) =
      delete;

  ~FingerprintAuthBlockService() = default;

  // Create a null instance of this service that will not have any of the
  // underlying services available and so will not be able to do anything.
  //
  // This is mostly useful in tests where you need a copy of the service but
  // don't actually need any fingerprint operations to work.
  static std::unique_ptr<FingerprintAuthBlockService> MakeNullService();

  // Start registers a given user to the fp_service and initiates a fingerprint
  // sensor session.
  void Start(ObfuscatedUsername obfuscated_username,
             PreparedAuthFactorToken::Consumer on_done);

  // Verify if the fingerprint sensor is currently in a "successfully
  // authorized" state or not.
  CryptohomeStatus Verify();

  // Terminate stops any ongoing fingerprint sensor session and
  // clears the registered user.
  void Terminate();

 private:
  // Token implementation used by the fingerprint service.
  class Token : public PreparedAuthFactorToken {
   public:
    Token();

    // Attaches the token to the underlying service. Ideally we'd do this in the
    // constructor but the token is constructed when we initiate the request to
    // start the session, not after the session is (successfully) started. We
    // don't want the token to be able to termination the session until it
    // starts, so we wait until that point to attach it.
    void AttachToService(FingerprintAuthBlockService* service);

   private:
    CryptohomeStatus TerminateAuthFactor() override;

    FingerprintAuthBlockService* service_ = nullptr;
    TerminateOnDestruction terminate_;
  };

  // Depending on the result of success, this will pass either the given auth
  // factor token, or a not-OK status to the given callback. This function is
  // designed to be used as a callback with FingerprintManager.
  void CheckSessionStartResult(std::unique_ptr<Token> token,
                               PreparedAuthFactorToken::Consumer on_done,
                               bool success);

  // Capture processes a fingerprint scan result. It records the scan result
  // and converts the result into a cryptohome signal status through
  // |scan_result_signal_callback_|. This function is designed to be
  // used by as a repeating callback with FingerprintManager.
  void Capture(FingerprintScanStatus status);

  // EndAuthSession terminates any ongoing fingerprint sensor session
  // and cancels all existing pending callbacks.
  void EndAuthSession();

  // TODO(b/276453357): Replace with FingerprintManager* once that object is
  // guaranteed to always be available.
  AsyncInitPtr<FingerprintManager> fp_manager_;

  // The most recent fingerprint scan result.
  FingerprintScanStatus scan_result_ =
      FingerprintScanStatus::FAILED_RETRY_NOT_ALLOWED;
  // The token for the currently active auth session, if there is one. This will
  // be set to null otherwise.
  PreparedAuthFactorToken* active_token_ = nullptr;
  // A callback to send cryptohome ScanResult signal.
  base::RepeatingCallback<void(user_data_auth::FingerprintScanResult)>
      signal_sender_;
};

// Implementation of the credential verifier API. Acts as a simple wrapper
// around the verify provided by the fingerprint service.
class FingerprintVerifier final : public AsyncCredentialVerifier {
 public:
  explicit FingerprintVerifier(FingerprintAuthBlockService* service);

 private:
  void VerifyAsync(const AuthInput& input,
                   StatusCallback callback) const override;

  FingerprintAuthBlockService* service_;
};

}  // namespace cryptohome

#endif  // CRYPTOHOME_AUTH_BLOCKS_FP_SERVICE_H_
