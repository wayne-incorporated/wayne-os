// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/aes.h"

#include <optional>
#include <string>

#include <base/strings/string_number_conversions.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "libhwsec-foundation/crypto/secure_blob_util.h"

using ::hwsec_foundation::AesDecryptSpecifyBlockMode;
using ::hwsec_foundation::AesEncryptSpecifyBlockMode;

namespace hwsec_foundation {

// This is not a known vector but a very simple test against the API.
TEST(AesTest, AesGcmTestSimple) {
  brillo::SecureBlob key(kAesGcm256KeySize);
  brillo::SecureBlob iv(kAesGcmIVSize);
  brillo::SecureBlob tag(kAesGcmTagSize);

  brillo::SecureBlob ciphertext(4096, '\0');

  std::string message = "I am encrypting this message.";
  brillo::SecureBlob plaintext(message.begin(), message.end());

  GetSecureRandom(key.data(), key.size());

  EXPECT_TRUE(AesGcmEncrypt(plaintext, /*ad=*/std::nullopt, key, &iv, &tag,
                            &ciphertext));

  // Validity check that the encryption actually did something.
  EXPECT_NE(ciphertext, plaintext);
  EXPECT_EQ(ciphertext.size(), plaintext.size());

  brillo::SecureBlob decrypted_plaintext(4096);
  EXPECT_TRUE(AesGcmDecrypt(ciphertext, /*ad=*/std::nullopt, tag, key, iv,
                            &decrypted_plaintext));

  EXPECT_EQ(plaintext, decrypted_plaintext);
}

TEST(AesTest, AesGcmTestWithAd) {
  brillo::SecureBlob key(kAesGcm256KeySize);
  brillo::SecureBlob iv(kAesGcmIVSize);
  brillo::SecureBlob tag(kAesGcmTagSize);

  brillo::SecureBlob ciphertext(4096, '\0');

  std::string message = "I am encrypting this message.";
  brillo::SecureBlob plaintext(message.begin(), message.end());

  std::string ad_value = "This is authentication data.";
  brillo::SecureBlob ad(ad_value.begin(), ad_value.end());

  GetSecureRandom(key.data(), key.size());

  EXPECT_TRUE(AesGcmEncrypt(plaintext, ad, key, &iv, &tag, &ciphertext));

  // Validity check that the encryption actually did something.
  EXPECT_NE(ciphertext, plaintext);
  EXPECT_EQ(ciphertext.size(), plaintext.size());

  brillo::SecureBlob decrypted_plaintext(4096);
  EXPECT_TRUE(
      AesGcmDecrypt(ciphertext, ad, tag, key, iv, &decrypted_plaintext));

  EXPECT_EQ(plaintext, decrypted_plaintext);
}

TEST(AesTest, AesGcmTestWrongAd) {
  brillo::SecureBlob key(kAesGcm256KeySize);
  brillo::SecureBlob iv(kAesGcmIVSize);
  brillo::SecureBlob tag(kAesGcmTagSize);

  brillo::SecureBlob ciphertext(4096, '\0');

  std::string message = "I am encrypting this message.";
  brillo::SecureBlob plaintext(message.begin(), message.end());

  std::string ad_value = "This is authentication data.";
  brillo::SecureBlob ad(ad_value.begin(), ad_value.end());

  GetSecureRandom(key.data(), key.size());

  EXPECT_TRUE(AesGcmEncrypt(plaintext, ad, key, &iv, &tag, &ciphertext));

  // Validity check that the encryption actually did something.
  EXPECT_NE(ciphertext, plaintext);
  EXPECT_EQ(ciphertext.size(), plaintext.size());

  std::string new_ad_value = "Wrong authentication data.";
  brillo::SecureBlob new_ad(new_ad_value.begin(), new_ad_value.end());
  {
    brillo::SecureBlob decrypted_plaintext(4096);
    EXPECT_FALSE(
        AesGcmDecrypt(ciphertext, new_ad, tag, key, iv, &decrypted_plaintext));
    EXPECT_NE(plaintext, decrypted_plaintext);
  }
  {
    brillo::SecureBlob decrypted_plaintext(4096);
    EXPECT_FALSE(AesGcmDecrypt(ciphertext, /*ad=*/std::nullopt, tag, key, iv,
                               &decrypted_plaintext));
    EXPECT_NE(plaintext, decrypted_plaintext);
  }
}

TEST(AesTest, AesGcmTestWrongKey) {
  brillo::SecureBlob key(kAesGcm256KeySize);
  brillo::SecureBlob iv(kAesGcmIVSize);
  brillo::SecureBlob tag(kAesGcmTagSize);

  brillo::SecureBlob ciphertext(4096, '\0');

  std::string message = "I am encrypting this message.";
  brillo::SecureBlob plaintext(message.begin(), message.end());

  GetSecureRandom(key.data(), key.size());

  EXPECT_TRUE(AesGcmEncrypt(plaintext, /*ad=*/std::nullopt, key, &iv, &tag,
                            &ciphertext));

  // Validity check that the encryption actually did something.
  EXPECT_NE(ciphertext, plaintext);
  EXPECT_EQ(ciphertext.size(), plaintext.size());

  brillo::SecureBlob wrong_key(kAesGcm256KeySize);
  GetSecureRandom(wrong_key.data(), wrong_key.size());

  brillo::SecureBlob decrypted_plaintext(4096);
  EXPECT_FALSE(AesGcmDecrypt(ciphertext, /*ad=*/std::nullopt, tag, wrong_key,
                             iv, &decrypted_plaintext));
  EXPECT_NE(plaintext, decrypted_plaintext);
}

TEST(AesTest, AesGcmTestWrongIV) {
  brillo::SecureBlob key(kAesGcm256KeySize);
  brillo::SecureBlob iv(kAesGcmIVSize);
  brillo::SecureBlob tag(kAesGcmTagSize);

  brillo::SecureBlob ciphertext(4096, '\0');

  std::string message = "I am encrypting this message.";
  brillo::SecureBlob plaintext(message.begin(), message.end());

  GetSecureRandom(key.data(), key.size());

  EXPECT_TRUE(AesGcmEncrypt(plaintext, /*ad=*/std::nullopt, key, &iv, &tag,
                            &ciphertext));

  // Validity check that the encryption actually did something.
  EXPECT_NE(ciphertext, plaintext);
  EXPECT_EQ(ciphertext.size(), plaintext.size());

  brillo::SecureBlob wrong_iv(kAesGcmIVSize);
  GetSecureRandom(wrong_iv.data(), wrong_iv.size());

  brillo::SecureBlob decrypted_plaintext(4096);
  EXPECT_FALSE(AesGcmDecrypt(ciphertext, /*ad=*/std::nullopt, tag, key,
                             wrong_iv, &decrypted_plaintext));
  EXPECT_NE(plaintext, decrypted_plaintext);
}

TEST(AesTest, AesGcmTestWrongTag) {
  brillo::SecureBlob key(kAesGcm256KeySize);
  brillo::SecureBlob iv(kAesGcmIVSize);
  brillo::SecureBlob tag(kAesGcmTagSize);

  brillo::SecureBlob ciphertext(4096, '\0');

  std::string message = "I am encrypting this message.";
  brillo::SecureBlob plaintext(message.begin(), message.end());

  GetSecureRandom(key.data(), key.size());

  EXPECT_TRUE(AesGcmEncrypt(plaintext, /*ad=*/std::nullopt, key, &iv, &tag,
                            &ciphertext));

  // Validity check that the encryption actually did something.
  EXPECT_NE(ciphertext, plaintext);
  EXPECT_EQ(ciphertext.size(), plaintext.size());

  brillo::SecureBlob wrong_tag(kAesGcmTagSize);
  GetSecureRandom(wrong_tag.data(), wrong_tag.size());

  brillo::SecureBlob decrypted_plaintext(4096);
  EXPECT_FALSE(AesGcmDecrypt(ciphertext, /*ad=*/std::nullopt, wrong_tag, key,
                             iv, &decrypted_plaintext));
}

// This tests that AesGcmEncrypt produces a different IV on subsequent runs.
// Note that this is in no way a mathematical test of secure randomness. It
// makes sure nobody in the future, for some reason, changes AesGcmEncrypt to
// use a fixed IV without tests failing, at which point they will find this
// test, and see that AesGcmEncrypt *must* return random IVs.
TEST(AesTest, AesGcmTestUniqueIVs) {
  brillo::SecureBlob key(kAesGcm256KeySize);
  brillo::SecureBlob tag(kAesGcmTagSize);

  brillo::SecureBlob ciphertext(4096, '\0');

  std::string message = "I am encrypting this message.";
  brillo::SecureBlob plaintext(message.begin(), message.end());

  GetSecureRandom(key.data(), key.size());

  brillo::SecureBlob iv(kAesGcmIVSize);
  EXPECT_TRUE(AesGcmEncrypt(plaintext, /*ad=*/std::nullopt, key, &iv, &tag,
                            &ciphertext));

  brillo::SecureBlob iv2(kAesGcmIVSize);
  EXPECT_TRUE(AesGcmEncrypt(plaintext, /*ad=*/std::nullopt, key, &iv2, &tag,
                            &ciphertext));

  brillo::SecureBlob iv3(kAesGcmIVSize);
  EXPECT_TRUE(AesGcmEncrypt(plaintext, /*ad=*/std::nullopt, key, &iv3, &tag,
                            &ciphertext));

  EXPECT_NE(iv, iv2);
  EXPECT_NE(iv, iv3);
}

// This is a validity check that AES-CTR-256 encryption encrypts and returns the
// same message.
TEST(AesTest, SimpleAesCtrEncryption) {
  std::string message = "ENCRYPT ME";
  brillo::SecureBlob key(32, 'A');
  brillo::SecureBlob iv(16, 'B');
  brillo::SecureBlob ciphertext;

  EXPECT_TRUE(AesEncryptSpecifyBlockMode(
      brillo::SecureBlob(message.begin(), message.end()), 0, message.size(),
      key, iv, PaddingScheme::kPaddingStandard, BlockMode::kCtr, &ciphertext));

  brillo::SecureBlob decrypted;
  EXPECT_TRUE(AesDecryptSpecifyBlockMode(ciphertext, 0, ciphertext.size(), key,
                                         iv, PaddingScheme::kPaddingStandard,
                                         BlockMode::kCtr, &decrypted));

  std::string decrypted_str(decrypted.begin(), decrypted.end());
  EXPECT_EQ(message, decrypted_str);
}

// Known test vectors for AES-256-CTR from
// https://boringssl.googlesource.com/boringssl/+/2490/crypto/cipher/test/cipher_test.txt#180
TEST(AesTest, AesCTRKnownVector1) {
  brillo::SecureBlob key = {
      0x77, 0x6B, 0xEF, 0xF2, 0x85, 0x1D, 0xB0, 0x6F, 0x4C, 0x8A, 0x05,
      0x42, 0xC8, 0x69, 0x6F, 0x6C, 0x6A, 0x81, 0xAF, 0x1E, 0xEC, 0x96,
      0xB4, 0xD3, 0x7F, 0xC1, 0xD6, 0x89, 0xE6, 0xC1, 0xC1, 0x04,
  };
  brillo::SecureBlob iv = {
      0x00, 0x00, 0x00, 0x60, 0xDB, 0x56, 0x72, 0xC9,
      0x7A, 0xA8, 0xF0, 0xB2, 0x00, 0x00, 0x00, 0x01,
  };
  brillo::SecureBlob plaintext = {
      0x53, 0x69, 0x6E, 0x67, 0x6C, 0x65, 0x20, 0x62,
      0x6C, 0x6F, 0x63, 0x6B, 0x20, 0x6D, 0x73, 0x67,
  };
  brillo::SecureBlob expected_ciphertext = {
      0x14, 0x5A, 0xD0, 0x1D, 0xBF, 0x82, 0x4E, 0xC7,
      0x56, 0x08, 0x63, 0xDC, 0x71, 0xE3, 0xE0, 0xC0,
  };
  brillo::SecureBlob ciphertext;

  EXPECT_TRUE(AesEncryptSpecifyBlockMode(plaintext, 0, plaintext.size(), key,
                                         iv, PaddingScheme::kPaddingStandard,
                                         BlockMode::kCtr, &ciphertext));

  EXPECT_EQ(expected_ciphertext, ciphertext);

  brillo::SecureBlob resulting_plaintext;
  EXPECT_TRUE(AesDecryptSpecifyBlockMode(
      expected_ciphertext, 0, expected_ciphertext.size(), key, iv,
      PaddingScheme::kPaddingStandard, BlockMode::kCtr, &resulting_plaintext));
  EXPECT_EQ(plaintext, resulting_plaintext);
}

TEST(AesTest, AesCTRKnownVector2) {
  brillo::SecureBlob key = {
      0xF6, 0xD6, 0x6D, 0x6B, 0xD5, 0x2D, 0x59, 0xBB, 0x07, 0x96, 0x36,
      0x58, 0x79, 0xEF, 0xF8, 0x86, 0xC6, 0x6D, 0xD5, 0x1A, 0x5B, 0x6A,
      0x99, 0x74, 0x4B, 0x50, 0x59, 0x0C, 0x87, 0xA2, 0x38, 0x84,
  };
  brillo::SecureBlob iv = {
      0x00, 0xFA, 0xAC, 0x24, 0xC1, 0x58, 0x5E, 0xF1,
      0x5A, 0x43, 0xD8, 0x75, 0x00, 0x00, 0x00, 0x01,
  };
  brillo::SecureBlob plaintext = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
      0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
      0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
  };
  brillo::SecureBlob expected_ciphertext = {
      0xF0, 0x5E, 0x23, 0x1B, 0x38, 0x94, 0x61, 0x2C, 0x49, 0xEE, 0x00,
      0x0B, 0x80, 0x4E, 0xB2, 0xA9, 0xB8, 0x30, 0x6B, 0x50, 0x8F, 0x83,
      0x9D, 0x6A, 0x55, 0x30, 0x83, 0x1D, 0x93, 0x44, 0xAF, 0x1C,
  };
  brillo::SecureBlob ciphertext;

  EXPECT_TRUE(AesEncryptSpecifyBlockMode(plaintext, 0, plaintext.size(), key,
                                         iv, PaddingScheme::kPaddingStandard,
                                         BlockMode::kCtr, &ciphertext));

  EXPECT_EQ(expected_ciphertext, ciphertext);

  brillo::SecureBlob resulting_plaintext;
  EXPECT_TRUE(AesDecryptSpecifyBlockMode(
      expected_ciphertext, 0, expected_ciphertext.size(), key, iv,
      PaddingScheme::kPaddingStandard, BlockMode::kCtr, &resulting_plaintext));
  EXPECT_EQ(plaintext, resulting_plaintext);
}

TEST(AesTest, AesCTRKnownVector3) {
  brillo::SecureBlob key = {
      0xFF, 0x7A, 0x61, 0x7C, 0xE6, 0x91, 0x48, 0xE4, 0xF1, 0x72, 0x6E,
      0x2F, 0x43, 0x58, 0x1D, 0xE2, 0xAA, 0x62, 0xD9, 0xF8, 0x05, 0x53,
      0x2E, 0xDF, 0xF1, 0xEE, 0xD6, 0x87, 0xFB, 0x54, 0x15, 0x3D,
  };
  brillo::SecureBlob iv = {
      0x00, 0x1C, 0xC5, 0xB7, 0x51, 0xA5, 0x1D, 0x70,
      0xA1, 0xC1, 0x11, 0x48, 0x00, 0x00, 0x00, 0x01,
  };
  brillo::SecureBlob plaintext = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
      0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23,
  };
  brillo::SecureBlob expected_ciphertext = {
      0xEB, 0x6C, 0x52, 0x82, 0x1D, 0x0B, 0xBB, 0xF7, 0xCE, 0x75, 0x94, 0x46,
      0x2A, 0xCA, 0x4F, 0xAA, 0xB4, 0x07, 0xDF, 0x86, 0x65, 0x69, 0xFD, 0x07,
      0xF4, 0x8C, 0xC0, 0xB5, 0x83, 0xD6, 0x07, 0x1F, 0x1E, 0xC0, 0xE6, 0xB8,
  };
  brillo::SecureBlob ciphertext;

  EXPECT_TRUE(AesEncryptSpecifyBlockMode(plaintext, 0, plaintext.size(), key,
                                         iv, PaddingScheme::kPaddingStandard,
                                         BlockMode::kCtr, &ciphertext));

  EXPECT_EQ(expected_ciphertext, ciphertext);

  brillo::SecureBlob resulting_plaintext;
  EXPECT_TRUE(AesDecryptSpecifyBlockMode(
      expected_ciphertext, 0, expected_ciphertext.size(), key, iv,
      PaddingScheme::kPaddingStandard, BlockMode::kCtr, &resulting_plaintext));
  EXPECT_EQ(plaintext, resulting_plaintext);
}

}  // namespace hwsec_foundation
