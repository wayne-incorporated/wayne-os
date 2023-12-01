// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/hkdf.h"

#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <openssl/sha.h>

namespace hwsec_foundation {

// Tests HKDF using RFC test case for SHA-256 hash:
// https://tools.ietf.org/html/rfc5869#appendix-A
TEST(HkdfTest, Hkdf) {
  constexpr HkdfHash kHash = HkdfHash::kSha256;
  constexpr size_t kKeyLen = 42;
  brillo::SecureBlob ikm, info, salt, prk, okm, expected_prk, expected_okm;
  ASSERT_TRUE(brillo::SecureBlob::HexStringToSecureBlob(
      "0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B", &ikm));
  ASSERT_TRUE(
      brillo::SecureBlob::HexStringToSecureBlob("F0F1F2F3F4F5F6F7F8F9", &info));
  ASSERT_TRUE(brillo::SecureBlob::HexStringToSecureBlob(
      "000102030405060708090A0B0C", &salt));
  ASSERT_TRUE(brillo::SecureBlob::HexStringToSecureBlob(
      "077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5",
      &expected_prk));
  ASSERT_TRUE(brillo::SecureBlob::HexStringToSecureBlob(
      "3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208"
      "D5B887185865",
      &expected_okm));

  EXPECT_TRUE(HkdfExtract(kHash, ikm, salt, &prk));
  EXPECT_EQ(prk, expected_prk);

  EXPECT_TRUE(HkdfExpand(kHash, prk, info, kKeyLen, &okm));
  EXPECT_EQ(okm, expected_okm);

  okm.clear();
  EXPECT_TRUE(Hkdf(kHash, ikm, info, salt, kKeyLen, &okm));
  EXPECT_EQ(okm, expected_okm);
}

// Tests Hkdf interface with resulting key length equal to SHA-256 hash size.
TEST(HkdfTest, HkdfKeyLengthEqualToHashSize) {
  constexpr HkdfHash kHash = HkdfHash::kSha256;
  brillo::SecureBlob key("test_key");
  brillo::SecureBlob salt("test_salt");
  brillo::SecureBlob info("test_info");
  brillo::SecureBlob result;
  EXPECT_TRUE(HkdfExtract(kHash, key, salt, &result));
  EXPECT_EQ(result.size(), SHA256_DIGEST_LENGTH);

  result.clear();
  EXPECT_TRUE(HkdfExpand(kHash, key, info, /*result_len=*/0, &result));
  EXPECT_EQ(result.size(), SHA256_DIGEST_LENGTH);

  result.clear();
  EXPECT_TRUE(Hkdf(kHash, key, info, salt, /*result_len=*/0, &result));
  EXPECT_EQ(result.size(), SHA256_DIGEST_LENGTH);
}

// Tests maximum resulting key length. According to RFC 5869, the length of the
// resulting key cannot exceed 255*hash size.
TEST(HkdfTest, HkdfKeyLengthTooBig) {
  constexpr HkdfHash kHash = HkdfHash::kSha256;
  constexpr size_t kKeyLen = 255 * SHA256_DIGEST_LENGTH + 1;
  brillo::SecureBlob key("test_key");
  brillo::SecureBlob salt("test_salt");
  brillo::SecureBlob info("test_info");
  brillo::SecureBlob result;

  EXPECT_FALSE(HkdfExpand(kHash, key, info, kKeyLen, &result));
  EXPECT_FALSE(Hkdf(kHash, key, info, salt, kKeyLen, &result));
}

// Tests Hkdf with empty info and salt. It is expected to be successful.
TEST(HkdfTest, HkdfWithEmptyInfoAndSalt) {
  constexpr HkdfHash kHash = HkdfHash::kSha256;
  constexpr size_t kKeyLen = 42;
  brillo::SecureBlob key("test_key");
  brillo::SecureBlob salt;
  brillo::SecureBlob info;
  brillo::SecureBlob result;

  EXPECT_TRUE(Hkdf(kHash, key, info, salt, kKeyLen, &result));
  EXPECT_EQ(result.size(), kKeyLen);
}

}  // namespace hwsec_foundation
