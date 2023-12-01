// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/key_objects.h"

#include <optional>

#include <brillo/secure_blob.h>
#include <gtest/gtest.h>

using brillo::SecureBlob;

namespace cryptohome {

namespace {

KeyBlobs GetFakeKeyBlobs() {
  return KeyBlobs{
      .vkk_key = SecureBlob("fake key"),
  };
}

KeyBlobs GetOtherFakeKeyBlobs() {
  return KeyBlobs{
      .vkk_key = SecureBlob("other fake key"),
  };
}

}  // namespace

// Test that `DeriveUssCredentialSecret()` succeeds and returns a nonempty
// result.
TEST(KeyBlobsTest, UssCredentialSecretDerivation) {
  const KeyBlobs key_blobs = GetFakeKeyBlobs();
  const std::optional<SecureBlob> uss_credential_secret =
      key_blobs.DeriveUssCredentialSecret();
  ASSERT_TRUE(uss_credential_secret.has_value());
  EXPECT_FALSE(uss_credential_secret.value().empty());
}

// Test that `DeriveUssCredentialSecret()` returns the same result for the same
// key blobs.
TEST(KeyBlobsTest, UssCredentialSecretDerivationStable) {
  const std::optional<SecureBlob> uss_credential_secret_1 =
      GetFakeKeyBlobs().DeriveUssCredentialSecret();
  const std::optional<SecureBlob> uss_credential_secret_2 =
      GetFakeKeyBlobs().DeriveUssCredentialSecret();
  EXPECT_EQ(uss_credential_secret_1, uss_credential_secret_2);
}

// Test that `DeriveUssCredentialSecret()` returns different results for
// different key blobs.
TEST(KeyBlobsTest, UssCredentialSecretDerivationNoCollision) {
  const KeyBlobs key_blobs_1 = GetFakeKeyBlobs();
  const std::optional<SecureBlob> uss_credential_secret_1 =
      key_blobs_1.DeriveUssCredentialSecret();

  const KeyBlobs key_blobs_2 = GetOtherFakeKeyBlobs();
  const std::optional<SecureBlob> uss_credential_secret_2 =
      key_blobs_2.DeriveUssCredentialSecret();

  EXPECT_NE(uss_credential_secret_1, uss_credential_secret_2);
}

// Test that `DeriveUssCredentialSecret()` fails gracefully for an empty key
// blob.
TEST(KeyBlobsTest, UssCredentialSecretDerivationEmptyFailure) {
  const KeyBlobs clear_key_blobs;
  EXPECT_FALSE(clear_key_blobs.DeriveUssCredentialSecret().has_value());

  const KeyBlobs empty_key_blobs = {.vkk_key = SecureBlob()};
  EXPECT_FALSE(empty_key_blobs.DeriveUssCredentialSecret().has_value());
}

}  // namespace cryptohome
