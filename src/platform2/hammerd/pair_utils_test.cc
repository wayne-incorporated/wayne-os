// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string.h>

#include <memory>
#include <string>
#include <vector>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "hammerd/mock_dbus_wrapper.h"
#include "hammerd/mock_pair_utils.h"
#include "hammerd/mock_update_fw.h"
#include "hammerd/pair_utils.h"

namespace hammerd {

namespace {
// Curve25519 test vector from the NaCl distribution.
const char kAlicePrivateStr[] =
    "77076D0A7318A57D3C16C17251B26645DF4C2F87EBC0992AB177FBA51DB92C2A";
const char kAlicePublicStr[] =
    "8520F0098930A754748B7DDCB43EF75A0DBF3A0D26381AF4EBA4A98EAA9B4E6A";
const char kBobPrivateStr[] =
    "5DAB087E624A8A4B79E17F8B83800EE66F3BB1292618B6FD1C2F8B27FF88E0EB";
const char kBobPublicStr[] =
    "DE9EDB7D7B7DC1B4D35B61C2ECE435373F8343C85B78674DADFC7E146F882B4F";

// Self-created test vector.
const char kNonceStr[] = "19A50A637080D93812AD65C8C5205786";
const char kAuthenticatorStr[] = "61372D572BC47539D1539AE0F395AAE3";
}  // namespace

using testing::_;
using testing::DoAll;
using testing::InSequence;
using testing::Return;

// Convert the test vector from Hex-encoded string to data.
class TestVector {
 public:
  TestVector() {
    base::HexStringToBytes(kAlicePrivateStr, &alice_private_);
    base::HexStringToBytes(kAlicePublicStr, &alice_public_);
    base::HexStringToBytes(kBobPrivateStr, &bob_private_);
    base::HexStringToBytes(kBobPublicStr, &bob_public_);
    base::HexStringToBytes(kNonceStr, &nonce_);
    base::HexStringToBytes(kAuthenticatorStr, &authenticator_);
  }

  std::vector<uint8_t> alice_private_;
  std::vector<uint8_t> alice_public_;
  std::vector<uint8_t> bob_private_;
  std::vector<uint8_t> bob_public_;
  std::vector<uint8_t> nonce_;
  std::vector<uint8_t> authenticator_;
};

// Check the size of destination and source is the same, and then copy the data.
void CheckMemcpy(uint8_t* dest, size_t size, const std::vector<uint8_t>& src) {
  ASSERT_EQ(size, src.size());
  memcpy(dest, src.data(), size);
}

ACTION_P3(SetChallengeRequest, public_key, private_key, nonce) {
  CheckMemcpy(arg0->public_key, X25519_PUBLIC_VALUE_LEN, public_key);
  CheckMemcpy(arg0->nonce, kHMACNonceLength, nonce);
  CheckMemcpy(arg1, X25519_PRIVATE_KEY_LEN, private_key);
}

ACTION_P4(SetChallengeResponse, status, public_key, authenticator, ret) {
  auto resp = reinterpret_cast<PairChallengeResponse*>(arg2);
  resp->status = static_cast<uint8_t>(status);
  if (public_key.size() > 0)
    CheckMemcpy(resp->public_key, X25519_PUBLIC_VALUE_LEN, public_key);
  if (authenticator.size() > 0)
    CheckMemcpy(resp->authenticator, kHMACAuthenticatorLength, authenticator);
  return ret;
}

// Verify PairManager method.
// In the normal case, the host side uses Alice's key, and Hammer side users
// Bob's key.
class PairTest : public testing::Test {
 public:
  void SetUp() override {
    // Make the request payload with Alice's key pair and the nonce.
    PairChallengeRequest fake_request;
    CheckMemcpy(fake_request.public_key, X25519_PUBLIC_VALUE_LEN,
                tv_.alice_public_);
    CheckMemcpy(fake_request.nonce, kHMACNonceLength, tv_.nonce_);
    request_payload_.assign(reinterpret_cast<const char*>(&fake_request),
                            sizeof(fake_request));

    // Always generate the request with Alice's key pair and the nonce.
    EXPECT_CALL(pair_manager_, GenerateChallenge(_, _))
        .WillRepeatedly(SetChallengeRequest(tv_.alice_public_,
                                            tv_.alice_private_, tv_.nonce_));
    // USB device is not disconnected in normal case.
    ON_CALL(fw_updater_, UsbSysfsExists()).WillByDefault(Return(true));
  }

 protected:
  MockPairManager pair_manager_;
  MockDBusWrapper dbus_wrapper_;
  std::string request_payload_;
  TestVector tv_;
  MockFirmwareUpdater fw_updater_;
};

// Hammer returns a valid response.
TEST_F(PairTest, ChallengePassed) {
  EXPECT_CALL(fw_updater_,
              SendSubcommandReceiveResponse(
                  UpdateExtraCommand::kPairChallenge, request_payload_, _,
                  sizeof(PairChallengeResponse), false))
      .WillOnce(SetChallengeResponse(EcResponseStatus::kSuccess,
                                     tv_.bob_public_, tv_.authenticator_,
                                     true));
  EXPECT_CALL(
      dbus_wrapper_,
      SendSignalWithArgHelper(kPairChallengeSucceededSignal, tv_.bob_public_));
  EXPECT_EQ(pair_manager_.PairChallenge(&fw_updater_, &dbus_wrapper_),
            ChallengeStatus::kChallengePassed);
}

// Hammer returns an invalid response. The correct response should contain Bob's
// public key but it returns Alice's public key.
TEST_F(PairTest, ChallengeFailed) {
  EXPECT_CALL(fw_updater_,
              SendSubcommandReceiveResponse(
                  UpdateExtraCommand::kPairChallenge, request_payload_, _,
                  sizeof(PairChallengeResponse), false))
      .WillOnce(SetChallengeResponse(EcResponseStatus::kSuccess,
                                     tv_.alice_public_, tv_.authenticator_,
                                     true));
  EXPECT_CALL(dbus_wrapper_, SendSignal(kPairChallengeFailedSignal));
  EXPECT_EQ(pair_manager_.PairChallenge(&fw_updater_, &dbus_wrapper_),
            ChallengeStatus::kChallengeFailed);
}

// Hammer only returns the kUnavailable status.
TEST_F(PairTest, ChallengeNeedInjectEntropy) {
  EXPECT_CALL(fw_updater_,
              SendSubcommandReceiveResponse(
                  UpdateExtraCommand::kPairChallenge, request_payload_, _,
                  sizeof(PairChallengeResponse), false))
      .WillOnce(SetChallengeResponse(EcResponseStatus::kUnavailable,
                                     std::vector<uint8_t>(),
                                     std::vector<uint8_t>(), false));
  EXPECT_EQ(pair_manager_.PairChallenge(&fw_updater_, &dbus_wrapper_),
            ChallengeStatus::kNeedInjectEntropy);
}

// Do not send DBus signal when the base is disconnected.
TEST_F(PairTest, UsbDisconnection) {
  // The base is disconnected.
  ON_CALL(fw_updater_, UsbSysfsExists()).WillByDefault(Return(false));

  EXPECT_CALL(fw_updater_,
              SendSubcommandReceiveResponse(
                  UpdateExtraCommand::kPairChallenge, request_payload_, _,
                  sizeof(PairChallengeResponse), false))
      .WillOnce(SetChallengeResponse(EcResponseStatus::kInvalidParam,
                                     std::vector<uint8_t>(),
                                     std::vector<uint8_t>(), false));
  // The DBus signal is not sent.
  EXPECT_CALL(dbus_wrapper_, SendSignal(_)).Times(0);
  EXPECT_EQ(pair_manager_.PairChallenge(&fw_updater_, &dbus_wrapper_),
            ChallengeStatus::kConnectionError);
}

// Hammer only returns the other error status.
TEST_F(PairTest, ChallengeUnknownError) {
  EXPECT_CALL(fw_updater_,
              SendSubcommandReceiveResponse(
                  UpdateExtraCommand::kPairChallenge, request_payload_, _,
                  sizeof(PairChallengeResponse), false))
      .WillOnce(SetChallengeResponse(EcResponseStatus::kInvalidParam,
                                     std::vector<uint8_t>(),
                                     std::vector<uint8_t>(), false));
  EXPECT_CALL(dbus_wrapper_, SendSignal(kPairChallengeFailedSignal));
  EXPECT_EQ(pair_manager_.PairChallenge(&fw_updater_, &dbus_wrapper_),
            ChallengeStatus::kUnknownError);
}
}  // namespace hammerd
