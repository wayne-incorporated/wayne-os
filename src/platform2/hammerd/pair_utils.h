// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef HAMMERD_PAIR_UTILS_H_
#define HAMMERD_PAIR_UTILS_H_

#include <gtest/gtest_prod.h>

#include "hammerd/curve25519.h"
#include "hammerd/dbus_wrapper.h"
#include "hammerd/update_fw.h"

namespace hammerd {

// The length of the HMAC nonce
constexpr size_t kHMACNonceLength = 16;
// The truncated length of the HMAC authenticator
constexpr size_t kHMACAuthenticatorLength = 16;

// Pair challenge (from host), note that the packet, with header, must fit
// in a single USB packet (64 bytes), so its maximum length is 50 bytes.
struct PairChallengeRequest {
  uint8_t public_key[X25519_PUBLIC_VALUE_LEN];  // X22519 public key from host
  uint8_t nonce[kHMACNonceLength];              // nonce to be used for HMAC
};
static_assert(sizeof(PairChallengeRequest) <= 50,
              "size of PairChallengeRequest must be <= 50 bytes");

// Pair challenge response (from device).
struct PairChallengeResponse {
  uint8_t status;                               // Returned status from EC
  uint8_t public_key[X25519_PUBLIC_VALUE_LEN];  // X25519 public key from device
  // Authentication output, the value should be:
  //   HMAC_SHA256(X25519(device_private, host_public), nonce)
  uint8_t authenticator[kHMACAuthenticatorLength];
} __attribute__((packed));

enum class ChallengeStatus {
  kChallengePassed,
  kChallengeFailed,
  kNeedInjectEntropy,
  kConnectionError,
  kUnknownError,
};

// The interface of pairing manager.
class PairManagerInterface {
 public:
  virtual ~PairManagerInterface() = default;
  // Generates the challange request and sends to the hammer. Then verifies the
  // challenge.
  virtual ChallengeStatus PairChallenge(FirmwareUpdaterInterface* fw_updater,
                                        DBusWrapperInterface* dbus_wrapper) = 0;
};

// The host for generating and verifying the challenge.
// In order to prevent the challenge reuse, PairManager does not store the
// request as data members.
class PairManager : public PairManagerInterface {
 public:
  PairManager() = default;
  PairManager(const PairManager&) = delete;
  PairManager& operator=(const PairManager&) = delete;

  ~PairManager() override = default;
  ChallengeStatus PairChallenge(FirmwareUpdaterInterface* fw_updater,
                                DBusWrapperInterface* dbus_wrapper) override;

 protected:
  virtual void GenerateChallenge(PairChallengeRequest* request,
                                 uint8_t* private_key);
  bool VerifyChallenge(const PairChallengeRequest& request,
                       uint8_t* private_key,
                       const PairChallengeResponse& resp);
};

}  // namespace hammerd
#endif  // HAMMERD_PAIR_UTILS_H_
