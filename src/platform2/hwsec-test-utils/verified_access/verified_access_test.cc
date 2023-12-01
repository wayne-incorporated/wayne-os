// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "hwsec-test-utils/verified_access/verified_access.h"

#include <brillo/data_encoding.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <optional>

#include "hwsec-test-utils/common/openssl_utility.h"
#include "hwsec-test-utils/well_known_key_pairs/well_known_key_pairs.h"

namespace hwsec_test_utils {

namespace {
// A real challenge response from a developer-mode device.
// clang-format off
  constexpr char kChallengeReponseBase64[] =
"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";
// clang-format on
}  // namespace

class VerifiedAccessChallengeTest : public testing::Test {
 public:
  VerifiedAccessChallengeTest() = default;
  ~VerifiedAccessChallengeTest() override = default;

 protected:
  verified_access::VerifiedAccessChallenge va_challenge_;
  attestation::SignedData challenge_response_;

  void SetupChallengeResponseToVerify() {
    std::string serialized;
    ASSERT_TRUE(brillo::data_encoding::Base64Decode(kChallengeReponseBase64,
                                                    &serialized));
    ASSERT_TRUE(challenge_response_.ParseFromString(serialized));
  }
};

TEST_F(VerifiedAccessChallengeTest, GenerateChallenge) {
  // Creates the output under test.
  constexpr char kExpectedPrefix[] = "prefix";
  std::optional<attestation::SignedData> optional_signed_data =
      va_challenge_.GenerateChallenge(kExpectedPrefix);
  ASSERT_TRUE(optional_signed_data.has_value());
  const attestation::SignedData& signed_data = *optional_signed_data;
  const std::string serialized_challenge = signed_data.data();
  attestation::Challenge challenge;
  ASSERT_TRUE(challenge.ParseFromString(serialized_challenge));

  // Verify data.
  EXPECT_EQ(challenge.prefix(), std::string(kExpectedPrefix));
  EXPECT_FALSE(challenge.nonce().empty());

  // Verify signature.
  crypto::ScopedEVP_PKEY key = well_known_key_pairs::GetVaSigningkey();
  ASSERT_NE(key.get(), nullptr);
  EXPECT_TRUE(EVPDigestVerify(key, EVP_sha256(), signed_data.data(),
                              signed_data.signature()));
}

// Tests |VerifyChallengeResponse| with the real response generated by a test
// image.
TEST_F(VerifiedAccessChallengeTest, VerifyChallengeResponse) {
  constexpr char kExpectedPrefix[] = "EnterpriseKeyChallenge";
  SetupChallengeResponseToVerify();
  EXPECT_TRUE(va_challenge_.VerifyChallengeResponse(challenge_response_,
                                                    kExpectedPrefix));
}

}  // namespace hwsec_test_utils
