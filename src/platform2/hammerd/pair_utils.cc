// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hammerd/pair_utils.h"

#include <string.h>

#include <string>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/threading/platform_thread.h>
#include <chromeos/dbus/service_constants.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace hammerd {

// Implementation of PairManager.
ChallengeStatus PairManager::PairChallenge(FirmwareUpdaterInterface* fw_updater,
                                           DBusWrapperInterface* dbus_wrapper) {
  // Generate Challenge request.
  PairChallengeRequest request;
  uint8_t private_key[X25519_PRIVATE_KEY_LEN];
  GenerateChallenge(&request, private_key);
  std::string request_payload(reinterpret_cast<const char*>(&request),
                              sizeof(request));

  // Send the request to the hammer.
  PairChallengeResponse response;
  if (!fw_updater->SendSubcommandReceiveResponse(
          UpdateExtraCommand::kPairChallenge, request_payload,
          reinterpret_cast<void*>(&response), sizeof(response))) {
    if (response.status ==
        static_cast<uint8_t>(EcResponseStatus::kUnavailable)) {
      LOG(ERROR) << "Need to inject the entropy.";
      // Because we will inject entropy and try to pair again, we don't send
      // kPairChallengeFailed signal here.
      return ChallengeStatus::kNeedInjectEntropy;
    }
    // If the base is disconnected, then do not send DBus message.
    // There is a short delay between device disconnected and kernel react to
    // it. Add a short delay before check.
    constexpr int kernel_delay_ms = 100;
    base::PlatformThread::Sleep(base::Milliseconds(kernel_delay_ms));
    if (!fw_updater->UsbSysfsExists()) {
      LOG(ERROR) << "USB device is disconnected.";
      return ChallengeStatus::kConnectionError;
    }
    LOG(ERROR) << "Unknown error! The status of response: "
               << static_cast<int>(response.status);
    dbus_wrapper->SendSignal(kPairChallengeFailedSignal);
    return ChallengeStatus::kUnknownError;
  }

  // Verify the response.
  if (VerifyChallenge(request, private_key, response)) {
    LOG(INFO) << "The pair challenge passed.";
    dbus_wrapper->SendSignalWithArg(kPairChallengeSucceededSignal,
                                    response.public_key,
                                    sizeof(response.public_key));
    return ChallengeStatus::kChallengePassed;
  }
  LOG(ERROR) << "The pair challenge failed.";
  dbus_wrapper->SendSignal(kPairChallengeFailedSignal);
  return ChallengeStatus::kChallengeFailed;
}

void PairManager::GenerateChallenge(PairChallengeRequest* request,
                                    uint8_t* private_key) {
  X25519_keypair(request->public_key, private_key);
  RAND_bytes(request->nonce, sizeof(request->nonce));
}

bool PairManager::VerifyChallenge(const PairChallengeRequest& request,
                                  uint8_t* private_key,
                                  const PairChallengeResponse& resp) {
  uint8_t shared[X25519_PRIVATE_KEY_LEN];
  uint8_t myauth[SHA256_DIGEST_LENGTH];

  X25519(shared, private_key, resp.public_key);

  HMAC(EVP_sha256(), shared, sizeof(shared), request.nonce,
       sizeof(request.nonce), myauth, nullptr);

  LOG(INFO) << "Authenticator (local):\n"
            << base::HexEncode(myauth, sizeof(myauth));
  // The authenticator is truncated, so we only compare the remaining part.
  static_assert(sizeof(resp.authenticator) <= SHA256_DIGEST_LENGTH,
                "size of authenticator must be <= SHA256_DIGEST_LENGTH.");
  if (memcmp(myauth, resp.authenticator, sizeof(resp.authenticator)) == 0) {
    LOG(INFO) << "Authenticator matches.";
    return true;
  }
  LOG(ERROR) << "Authenticator does not match (remote):"
             << base::HexEncode(resp.authenticator, sizeof(resp.authenticator));
  return false;
}

}  // namespace hammerd
