// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_factor/verifiers/scrypt.h"

#include <memory>
#include <variant>

#include <brillo/secure_blob.h>
#include <gtest/gtest.h>

#include "cryptohome/auth_factor/auth_factor_type.h"

namespace cryptohome {
namespace {

constexpr char kLabel[] = "fake-label";

class ScryptVerifierTest : public ::testing::Test {
 public:
  ScryptVerifierTest()
      : verifier_(ScryptVerifier::Create(kLabel, brillo::SecureBlob("good"))) {}

 protected:
  std::unique_ptr<ScryptVerifier> verifier_;
};

TEST_F(ScryptVerifierTest, AuthFactorType) {
  EXPECT_EQ(verifier_->auth_factor_type(), AuthFactorType::kPassword);
}

TEST_F(ScryptVerifierTest, AuthFactorLabel) {
  EXPECT_EQ(verifier_->auth_factor_label(), kLabel);
}

TEST_F(ScryptVerifierTest, AuthFactorMetadata) {
  EXPECT_TRUE(std::holds_alternative<auth_factor::PasswordMetadata>(
      verifier_->auth_factor_metadata().metadata));
}

TEST_F(ScryptVerifierTest, Ok) {
  AuthInput secret = {.user_input = brillo::SecureBlob("good")};
  EXPECT_TRUE(verifier_->Verify(secret));
}

TEST_F(ScryptVerifierTest, FailWithBadSecret) {
  AuthInput wrong_secret = {.user_input = brillo::SecureBlob("wrong")};
  EXPECT_FALSE(verifier_->Verify(wrong_secret));
}

TEST_F(ScryptVerifierTest, FailWithNoSecret) {
  AuthInput no_secret;
  EXPECT_FALSE(verifier_->Verify(no_secret));
}

}  // namespace
}  // namespace cryptohome
