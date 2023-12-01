// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/encryption/testing_primitives.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include <base/strings/string_piece.h>
#include <crypto/scoped_openssl_types.h>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include "missive/encryption/primitives.h"

namespace reporting {
namespace test {

void GenerateEncryptionKeyPair(uint8_t private_key[kKeySize],
                               uint8_t public_value[kKeySize]) {
  const crypto::ScopedEVP_PKEY_CTX pctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
  ASSERT_NE(pctx, nullptr);
  ASSERT_EQ(EVP_PKEY_keygen_init(pctx.get()), 1);
  EVP_PKEY* pk = nullptr;
  EXPECT_EQ(EVP_PKEY_keygen(pctx.get(), &pk), 1);
  ASSERT_NE(pk, nullptr);
  const crypto::ScopedEVP_PKEY pkey(pk);
  size_t len = kKeySize;
  EXPECT_EQ(EVP_PKEY_get_raw_private_key(pkey.get(), private_key, &len), 1);
  EXPECT_EQ(len, kKeySize);
  EXPECT_EQ(EVP_PKEY_get_raw_public_key(pkey.get(), public_value, &len), 1);
  EXPECT_EQ(len, kKeySize);
}

void RestoreSharedSecret(const uint8_t private_key[kKeySize],
                         const uint8_t peer_public_value[kKeySize],
                         uint8_t shared_secret[kKeySize]) {
  // Create private key.
  const crypto::ScopedEVP_PKEY local_key_pair(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_X25519, nullptr, private_key, kKeySize));
  ASSERT_NE(local_key_pair, nullptr);

  // Create peer public key.
  const crypto::ScopedEVP_PKEY peer_public_key(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, peer_public_value, kKeySize));
  ASSERT_NE(peer_public_key, nullptr);

  size_t shared_secret_len = kKeySize;
  const crypto::ScopedEVP_PKEY_CTX pctx(
      EVP_PKEY_CTX_new(local_key_pair.get(), nullptr));
  ASSERT_NE(pctx, nullptr);
  ASSERT_EQ(EVP_PKEY_derive_init(pctx.get()), 1);
  EXPECT_EQ(EVP_PKEY_derive_set_peer(pctx.get(), peer_public_key.get()), 1);
  EXPECT_EQ(EVP_PKEY_derive(pctx.get(), shared_secret, &shared_secret_len), 1);
  EXPECT_EQ(shared_secret_len, kKeySize);
}

void PerformSymmetricDecryption(const uint8_t symmetric_key[kKeySize],
                                base::StringPiece input_data,
                                std::string* output_data) {
  // Initialize decryption context.
  const crypto::ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
  ASSERT_NE(ctx, nullptr);

  // Initialize the decryption operation and key.
  ASSERT_GE(input_data.size(), kNonceSize + kAeadTagSize);
  EXPECT_EQ(EVP_DecryptInit_ex(
                ctx.get(), EVP_chacha20_poly1305(), nullptr, symmetric_key,
                /*nonce=*/reinterpret_cast<const uint8_t*>(input_data.data())),
            1);

  // Provide the message to be decrypted, and obtain the plaintext output.
  int len = input_data.size() - kNonceSize - kAeadTagSize;
  output_data->resize(len);
  EXPECT_EQ(
      EVP_DecryptUpdate(
          ctx.get(), reinterpret_cast<uint8_t*>(output_data->data()), &len,
          reinterpret_cast<const uint8_t*>(input_data.data() + kNonceSize),
          input_data.size() - kNonceSize - kAeadTagSize),
      1);
  EXPECT_EQ(len, input_data.size() - kNonceSize - kAeadTagSize);

  // Set the tag stored at the end of the encrypted record.
  EXPECT_EQ(EVP_CIPHER_CTX_ctrl(
                ctx.get(), EVP_CTRL_AEAD_SET_TAG, kAeadTagSize,
                // Tag is read from input_data, but
                // EVP_CIPHER_CTX_ctrl expects non-constant parameter
                const_cast<char*>(input_data.data()) + kNonceSize + len),
            1);

  // Finalize the decryption.
  len = 0;
  EXPECT_EQ(EVP_DecryptFinal_ex(
                ctx.get(),
                reinterpret_cast<uint8_t*>(output_data->data()) + len, &len),
            1);
  EXPECT_EQ(len, 0);
}

void GenerateSigningKeyPair(uint8_t private_key[kSignKeySize],
                            uint8_t public_value[kKeySize]) {
  // Generate new pair of private key and public value.
  const crypto::ScopedEVP_PKEY_CTX pctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
  ASSERT_NE(pctx, nullptr);
  ASSERT_EQ(EVP_PKEY_keygen_init(pctx.get()), 1);
  EVP_PKEY* pk = nullptr;
  EXPECT_EQ(EVP_PKEY_keygen(pctx.get(), &pk), 1);
  ASSERT_NE(pk, nullptr);
  const crypto::ScopedEVP_PKEY pkey(pk);
  size_t len = kSignKeySize;
  EXPECT_EQ(EVP_PKEY_get_raw_private_key(pkey.get(), private_key, &len), 1);
  EXPECT_EQ(len, kSignKeySize);
  len = kKeySize;
  EXPECT_EQ(EVP_PKEY_get_raw_public_key(pkey.get(), public_value, &len), 1);
  EXPECT_EQ(len, kKeySize);
}

void SignMessage(const uint8_t signing_key[kSignKeySize],
                 base::StringPiece message,
                 uint8_t signature[kSignatureSize]) {
  const crypto::ScopedEVP_PKEY sign_private_key(EVP_PKEY_new_raw_private_key(
      EVP_PKEY_ED25519, nullptr, signing_key, kSignKeySize));
  ASSERT_NE(sign_private_key, nullptr);
  const crypto::ScopedEVP_MD_CTX mdctx(EVP_MD_CTX_create());
  ASSERT_NE(mdctx, nullptr);
  EXPECT_EQ(EVP_DigestSignInit(mdctx.get(), nullptr, nullptr, nullptr,
                               sign_private_key.get()),
            1);
  size_t slen = kSignatureSize;
  EXPECT_EQ(EVP_DigestSign(mdctx.get(), signature, &slen,
                           reinterpret_cast<const uint8_t*>(message.data()),
                           message.size()),
            1);
  EXPECT_EQ(slen, kSignatureSize);
}

}  // namespace test
}  // namespace reporting
