// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/ecdh_hkdf.h"

#include <optional>

#include <gtest/gtest.h>

#include "libhwsec-foundation/crypto/aes.h"
#include "libhwsec-foundation/crypto/big_num_util.h"

namespace hwsec_foundation {

namespace {
constexpr EllipticCurve::CurveType kCurve = EllipticCurve::CurveType::kPrime256;
constexpr HkdfHash kHkdfHash = HkdfHash::kSha256;
const size_t kEcdhHkdfKeySize = kAesGcm256KeySize;

static const char kSaltHex[] = "0b0b0b0b";
static const char kInfoHex[] = "0b0b0b0b0b0b0b0b";
}  // namespace

TEST(EcdhHkdfTest, CompareEcdhHkdfSymmetricKeys) {
  ScopedBN_CTX context = CreateBigNumContext();
  ASSERT_TRUE(context);
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(kCurve, context.get());
  ASSERT_TRUE(ec);

  brillo::SecureBlob info;
  ASSERT_TRUE(brillo::SecureBlob::HexStringToSecureBlob(kInfoHex, &info));
  brillo::SecureBlob salt;
  ASSERT_TRUE(brillo::SecureBlob::HexStringToSecureBlob(kSaltHex, &salt));

  brillo::SecureBlob symmetric_key1;
  brillo::SecureBlob symmetric_key2;

  crypto::ScopedEC_KEY rec_key_pair = ec->GenerateKey(context.get());
  const BIGNUM* rec_priv_key = EC_KEY_get0_private_key(rec_key_pair.get());
  ASSERT_TRUE(rec_priv_key);
  const EC_POINT* rec_pub_key = EC_KEY_get0_public_key(rec_key_pair.get());
  ASSERT_TRUE(rec_pub_key);
  crypto::ScopedEC_KEY eph_key_pair = ec->GenerateKey(context.get());
  ASSERT_TRUE(eph_key_pair);
  const BIGNUM* eph_priv_key = EC_KEY_get0_private_key(eph_key_pair.get());
  ASSERT_TRUE(eph_priv_key);
  const EC_POINT* eph_pub_key = EC_KEY_get0_public_key(eph_key_pair.get());
  ASSERT_TRUE(eph_pub_key);
  brillo::SecureBlob eph_pub_key_blob;
  ASSERT_TRUE(
      ec->EncodeToSpkiDer(eph_key_pair, &eph_pub_key_blob, context.get()));

  crypto::ScopedEC_POINT shared_secret_point_sender =
      ComputeEcdhSharedSecretPoint(*ec, *rec_pub_key, *eph_priv_key);
  ASSERT_TRUE(shared_secret_point_sender);
  ASSERT_TRUE(GenerateEcdhHkdfSymmetricKey(
      *ec, *shared_secret_point_sender, eph_pub_key_blob, info, salt, kHkdfHash,
      kEcdhHkdfKeySize, &symmetric_key1));

  crypto::ScopedEC_POINT shared_secret_point_recipient =
      ComputeEcdhSharedSecretPoint(*ec, *eph_pub_key, *rec_priv_key);
  ASSERT_TRUE(shared_secret_point_recipient);
  ASSERT_TRUE(GenerateEcdhHkdfSymmetricKey(
      *ec, *shared_secret_point_recipient, eph_pub_key_blob, info, salt,
      kHkdfHash, kEcdhHkdfKeySize, &symmetric_key2));

  EXPECT_EQ(symmetric_key1.size(), kAesGcm256KeySize);
  EXPECT_EQ(symmetric_key2.size(), kAesGcm256KeySize);

  // Symmetric keys generated for sender and recipient should be equal.
  EXPECT_EQ(symmetric_key1, symmetric_key2);
}

TEST(EcdhHkdfTest, AesGcmEncryptionDecryption) {
  ScopedBN_CTX context = CreateBigNumContext();
  ASSERT_TRUE(context);
  std::optional<EllipticCurve> ec =
      EllipticCurve::Create(kCurve, context.get());
  ASSERT_TRUE(ec);

  brillo::SecureBlob info;
  ASSERT_TRUE(brillo::SecureBlob::HexStringToSecureBlob(kInfoHex, &info));
  brillo::SecureBlob salt;
  ASSERT_TRUE(brillo::SecureBlob::HexStringToSecureBlob(kSaltHex, &salt));

  crypto::ScopedEC_KEY rec_key_pair = ec->GenerateKey(context.get());
  const BIGNUM* rec_priv_key = EC_KEY_get0_private_key(rec_key_pair.get());
  ASSERT_TRUE(rec_priv_key);
  const EC_POINT* rec_pub_key = EC_KEY_get0_public_key(rec_key_pair.get());
  ASSERT_TRUE(rec_pub_key);
  crypto::ScopedEC_KEY eph_key_pair = ec->GenerateKey(context.get());
  const BIGNUM* eph_priv_key = EC_KEY_get0_private_key(eph_key_pair.get());
  ASSERT_TRUE(eph_priv_key);
  const EC_POINT* eph_pub_key = EC_KEY_get0_public_key(eph_key_pair.get());
  ASSERT_TRUE(eph_pub_key);
  brillo::SecureBlob eph_pub_key_blob;
  ASSERT_TRUE(
      ec->EncodeToSpkiDer(eph_key_pair, &eph_pub_key_blob, context.get()));
  brillo::SecureBlob aes_gcm_key1;
  brillo::SecureBlob aes_gcm_key2;

  crypto::ScopedEC_POINT shared_secret_point_sender =
      ComputeEcdhSharedSecretPoint(*ec, *rec_pub_key, *eph_priv_key);
  ASSERT_TRUE(GenerateEcdhHkdfSymmetricKey(
      *ec, *shared_secret_point_sender, eph_pub_key_blob, info, salt, kHkdfHash,
      kEcdhHkdfKeySize, &aes_gcm_key1));

  brillo::SecureBlob iv(kAesGcmIVSize);
  brillo::SecureBlob tag(kAesGcmTagSize);
  brillo::SecureBlob ciphertext;
  brillo::SecureBlob plaintext("I am encrypting this message.");

  // Encrypt using sender's `aes_gcm_key1`.
  EXPECT_TRUE(AesGcmEncrypt(plaintext, /*ad=*/std::nullopt, aes_gcm_key1, &iv,
                            &tag, &ciphertext));

  crypto::ScopedEC_POINT shared_secret_point_recipient =
      ComputeEcdhSharedSecretPoint(*ec, *eph_pub_key, *rec_priv_key);
  ASSERT_TRUE(GenerateEcdhHkdfSymmetricKey(
      *ec, *shared_secret_point_recipient, eph_pub_key_blob, info, salt,
      kHkdfHash, kEcdhHkdfKeySize, &aes_gcm_key2));

  // Symmetric keys generated for sender and recipient should be equal.
  EXPECT_EQ(aes_gcm_key1, aes_gcm_key2);

  EXPECT_NE(ciphertext, plaintext);
  EXPECT_EQ(ciphertext.size(), plaintext.size());

  // Decrypt using recipient's `aes_gcm_key2`.
  brillo::SecureBlob decrypted_plaintext;
  EXPECT_TRUE(AesGcmDecrypt(ciphertext, /*ad=*/std::nullopt, tag, aes_gcm_key2,
                            iv, &decrypted_plaintext));

  EXPECT_EQ(plaintext, decrypted_plaintext);
}

}  // namespace hwsec_foundation
