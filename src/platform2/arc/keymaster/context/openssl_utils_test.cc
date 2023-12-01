// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/context/openssl_utils.h"

#include <optional>

#include <brillo/secure_blob.h>
#include <gtest/gtest.h>

namespace arc {
namespace keymaster {
namespace context {

namespace {

// Arbitrary 32 byte keys.
const brillo::SecureBlob kEncryptionKey1(32, 99);
const brillo::SecureBlob kEncryptionKey2(32, 98);
// Arbitrary byte arrays.
const brillo::Blob kAuthData1 = {1, 2, 3};
const brillo::Blob kAuthData2 = {1, 2, 4};
const brillo::SecureBlob kBlob(145, 42);

}  // anonymous namespace

TEST(OpenSslUtils, EncryptThenDecrypt) {
  // Encrypt.
  std::optional<brillo::Blob> encrypted =
      Aes256GcmEncrypt(kEncryptionKey1, kAuthData1, kBlob);
  ASSERT_TRUE(encrypted.has_value());

  // Decrypt.
  std::optional<brillo::SecureBlob> decrypted =
      Aes256GcmDecrypt(kEncryptionKey1, kAuthData1, encrypted.value());
  ASSERT_TRUE(decrypted.has_value());

  // Verify blobs before encryption and after decryption match.
  ASSERT_EQ(kBlob, decrypted.value());
}

TEST(OpenSslUtils, EncryptedBlobSize) {
  // Encrypt.
  std::optional<brillo::Blob> encrypted =
      Aes256GcmEncrypt(kEncryptionKey1, kAuthData1, kBlob);
  ASSERT_TRUE(encrypted.has_value());

  // Verify encrypted blob is large enough to contain auth tag and IV.
  EXPECT_GE(encrypted->size(), kBlob.size() + kTagSize + kIvSize);
}

TEST(OpenSslUtils, DecryptWithDifferentEncryptionKeyError) {
  // Encrypt with some encryption key.
  std::optional<brillo::Blob> encrypted =
      Aes256GcmEncrypt(kEncryptionKey1, kAuthData1, kBlob);
  ASSERT_TRUE(encrypted.has_value());

  // Try to decrypt with another encryption key.
  ASSERT_NE(kEncryptionKey1, kEncryptionKey2);
  std::optional<brillo::SecureBlob> decrypted =
      Aes256GcmDecrypt(kEncryptionKey2, kAuthData1, encrypted.value());

  // Verify decryption fails.
  EXPECT_FALSE(decrypted.has_value());
}

TEST(OpenSslUtils, DecryptWithDifferentAuthDataError) {
  // Encrypt with some auth data.
  std::optional<brillo::Blob> encrypted =
      Aes256GcmEncrypt(kEncryptionKey1, kAuthData1, kBlob);
  ASSERT_TRUE(encrypted.has_value());

  // Try to decrypt with different auth data.
  ASSERT_NE(kAuthData1, kAuthData2);
  std::optional<brillo::SecureBlob> decrypted =
      Aes256GcmDecrypt(kEncryptionKey1, kAuthData2, encrypted.value());

  // Verify decryption fails.
  EXPECT_FALSE(decrypted.has_value());
}

}  // namespace context
}  // namespace keymaster
}  // namespace arc
