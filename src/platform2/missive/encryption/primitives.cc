// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "missive/encryption/primitives.h"

#include <cstddef>
#include <cstdint>
#include <string>

#include <crypto/scoped_openssl_types.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#include <base/strings/string_piece.h>

namespace reporting {

bool ComputeSharedSecret(const uint8_t peer_public_value[kKeySize],
                         uint8_t shared_secret[kKeySize],
                         uint8_t generated_public_value[kKeySize]) {
  // Generate new pair of private key and public value.
  EVP_PKEY* pk = nullptr;
  const crypto::ScopedEVP_PKEY_CTX pctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
  if (!pctx || 1 != EVP_PKEY_keygen_init(pctx.get()) ||
      1 != EVP_PKEY_keygen(pctx.get(), &pk)) {
    return false;
  }
  const crypto::ScopedEVP_PKEY out_local_key_pair(pk);
  if (!out_local_key_pair) {
    return false;
  }

  // Export public value from the generated pair.
  size_t generated_public_value_len = kKeySize;
  if (1 != EVP_PKEY_get_raw_public_key(out_local_key_pair.get(),
                                       generated_public_value,
                                       &generated_public_value_len) ||
      generated_public_value_len != kKeySize) {
    return false;
  }

  // Accept peer public value.
  const crypto::ScopedEVP_PKEY peer_public_key(EVP_PKEY_new_raw_public_key(
      EVP_PKEY_X25519, nullptr, peer_public_value, kKeySize));
  if (!peer_public_key) {
    return false;
  }

  // Compute shared secret.
  size_t shared_secret_len = kKeySize;
  {
    const crypto::ScopedEVP_PKEY_CTX pctx(
        EVP_PKEY_CTX_new(out_local_key_pair.get(), nullptr));
    if (!pctx || 1 != EVP_PKEY_derive_init(pctx.get()) ||
        1 != EVP_PKEY_derive_set_peer(pctx.get(), peer_public_key.get()) ||
        1 != EVP_PKEY_derive(pctx.get(), shared_secret, &shared_secret_len) ||
        shared_secret_len != kKeySize) {
      return false;
    }
  }
  return true;
}

bool ProduceSymmetricKey(const uint8_t shared_secret[kKeySize],
                         uint8_t symmetric_key[kKeySize]) {
  // Since the keys above are only used once, no salt and context is provided.
  const crypto::ScopedEVP_PKEY_CTX pctx(
      EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
  if (!pctx || 1 != EVP_PKEY_derive_init(pctx.get()) ||
      1 != EVP_PKEY_CTX_set_hkdf_md(pctx.get(), EVP_sha256()) ||
      1 != EVP_PKEY_CTX_set1_hkdf_key(pctx.get(), shared_secret, kKeySize) ||
      1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx.get(), /*salt=*/nullptr,
                                       /*saltlen=*/0) ||
      1 != EVP_PKEY_CTX_add1_hkdf_info(pctx.get(), /*info=*/nullptr,
                                       /*infolen=*/0)) {
    return false;
  }
  size_t symmetric_key_len = kKeySize;
  if (1 != EVP_PKEY_derive(pctx.get(), symmetric_key, &symmetric_key_len) ||
      symmetric_key_len != kKeySize) {
    return false;
  }
  return true;
}

bool PerformSymmetricEncryption(const uint8_t symmetric_key[kKeySize],
                                base::StringPiece input_data,
                                std::string* output_data) {
  // Initialize encryption context.
  const crypto::ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
  if (!ctx) {
    return false;
  }

  // Reserve space for encrypted result: nonce, encrypted bytes, authentication
  // tag.
  output_data->resize(kNonceSize + input_data.size() + kAeadTagSize);

  // Initialize the encryption operation and key. Set nonce to all zeroes, since
  // a symmetric key is only used once. Note: if we ever start reusing the same
  // symmetric key, we will need to generate new nonce for every record and
  // transfer it to the peer.
  memset(output_data->data(), 0, kNonceSize);
  if (1 !=
      EVP_EncryptInit_ex(
          ctx.get(), EVP_chacha20_poly1305(), nullptr, symmetric_key,
          /*nonce=*/reinterpret_cast<const uint8_t*>(output_data->data()))) {
    return false;
  }

  // Provide the message to be encrypted, and obtain the encrypted output_data.
  int output_len = input_data.size();
  if (1 != EVP_EncryptUpdate(
               ctx.get(),
               reinterpret_cast<uint8_t*>(output_data->data() + kNonceSize),
               &output_len, reinterpret_cast<const uint8_t*>(input_data.data()),
               input_data.size()) ||
      output_len != input_data.size()) {
    return false;
  }

  // Finalize the encryption.
  output_len = 0;
  int ret = EVP_EncryptFinal_ex(
      ctx.get(),
      reinterpret_cast<uint8_t*>(output_data->data()) + input_data.size(),
      &output_len);
  if (ret <= 0 || output_len != 0) {
    return false;
  }

  // Get the tag and attach it at the end of the encrypted record.
  if (1 != EVP_CIPHER_CTX_ctrl(
               ctx.get(), EVP_CTRL_AEAD_GET_TAG, kAeadTagSize,
               output_data->data() + kNonceSize + input_data.size())) {
    return false;
  }

  return true;
}

bool VerifySignature(const uint8_t verification_key[kKeySize],
                     base::StringPiece message,
                     const uint8_t signature[kSignatureSize]) {
  // Create the Message Digest Context
  const crypto::ScopedEVP_MD_CTX mdctx(EVP_MD_CTX_create());
  if (!mdctx) {
    return false;
  }

  // Initialize with the verification key.
  const crypto::ScopedEVP_PKEY verification_public_key(
      EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, verification_key,
                                  kKeySize));
  if (!verification_public_key ||
      1 != EVP_DigestVerifyInit(
               mdctx.get(), nullptr,
               nullptr,  // digest set to nullptr: ED25519 does not support any
               nullptr, verification_public_key.get())) {
    return false;
  }

  // Verify the message.
  if (1 != EVP_DigestVerify(mdctx.get(), signature, kSignatureSize,
                            reinterpret_cast<const uint8_t*>(message.data()),
                            message.size())) {
    return false;
  }

  return true;
}

}  // namespace reporting
