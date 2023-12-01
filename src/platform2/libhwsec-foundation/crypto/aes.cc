// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/aes.h"

#include <limits>
#include <optional>

#include "libhwsec-foundation/crypto/secure_blob_util.h"

#include <base/logging.h>
#include <base/notreached.h>
#include <crypto/scoped_openssl_types.h>
#include <openssl/err.h>
#include <openssl/evp.h>

namespace hwsec_foundation {

size_t GetAesBlockSize() {
  return EVP_CIPHER_block_size(EVP_aes_256_cbc());
}

bool PasskeyToAesKey(const brillo::SecureBlob& passkey,
                     const brillo::SecureBlob& salt,
                     unsigned int rounds,
                     brillo::SecureBlob* key,
                     brillo::SecureBlob* iv) {
  if (salt.size() != PKCS5_SALT_LEN) {
    LOG(ERROR) << "Bad salt size.";
    return false;
  }

  const EVP_CIPHER* cipher = EVP_aes_256_cbc();
  brillo::SecureBlob aes_key(EVP_CIPHER_key_length(cipher));
  brillo::SecureBlob local_iv(EVP_CIPHER_iv_length(cipher));

  // Convert the passkey to a key
  if (!EVP_BytesToKey(cipher, EVP_sha1(), salt.data(), passkey.data(),
                      passkey.size(), rounds, aes_key.data(),
                      local_iv.data())) {
    LOG(ERROR) << "Failure converting bytes to key";
    return false;
  }

  key->swap(aes_key);
  if (iv) {
    iv->swap(local_iv);
  }

  return true;
}

bool AesEncryptDeprecated(const brillo::SecureBlob& plaintext,
                          const brillo::SecureBlob& key,
                          const brillo::SecureBlob& iv,
                          brillo::SecureBlob* ciphertext) {
  return AesEncryptSpecifyBlockMode(
      plaintext, 0, plaintext.size(), key, iv,
      PaddingScheme::kPaddingCryptohomeDefaultDeprecated, BlockMode::kCbc,
      ciphertext);
}

bool AesDecryptDeprecated(const brillo::SecureBlob& ciphertext,
                          const brillo::SecureBlob& key,
                          const brillo::SecureBlob& iv,
                          brillo::SecureBlob* plaintext) {
  return AesDecryptSpecifyBlockMode(
      ciphertext, 0, ciphertext.size(), key, iv,
      PaddingScheme::kPaddingCryptohomeDefaultDeprecated, BlockMode::kCbc,
      plaintext);
}

bool AesGcmDecrypt(const brillo::SecureBlob& ciphertext,
                   const std::optional<brillo::SecureBlob>& ad,
                   const brillo::SecureBlob& tag,
                   const brillo::SecureBlob& key,
                   const brillo::SecureBlob& iv,
                   brillo::SecureBlob* plaintext) {
  if (ciphertext.empty()) {
    NOTREACHED() << "Empty ciphertext passed to AesGcmDecrypt.";
    return false;
  }
  if (tag.size() != kAesGcmTagSize) {
    NOTREACHED() << "Wrong tag size passed to AesGcmDecrypt: " << tag.size()
                 << ", expected " << kAesGcmTagSize << ".";
    return false;
  }
  if (key.size() != kAesGcm256KeySize) {
    NOTREACHED() << "Wrong key size passed to AesGcmDecrypt: " << key.size()
                 << ", expected " << kAesGcm256KeySize << ".";
    return false;
  }
  if (iv.size() != kAesGcmIVSize) {
    NOTREACHED() << "Wrong iv size passed to AesGcmDecrypt: " << iv.size()
                 << ", expected " << kAesGcmIVSize << ".";
    return false;
  }

  crypto::ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    LOG(ERROR) << "Failed to create cipher ctx.";
    return false;
  }

  if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1) {
    LOG(ERROR) << "Failed to init decrypt.";
    return false;
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kAesGcmIVSize,
                          nullptr) != 1) {
    LOG(ERROR) << "Failed to set iv size.";
    return false;
  }

  if (EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv.data()) !=
      1) {
    LOG(ERROR) << "Failed to add key and iv to decrypt operation.";
    return false;
  }

  if (ad.has_value()) {
    if (ad.value().empty()) {
      NOTREACHED() << "Empty associated data passed to AesGcmDecrypt.";
      return false;
    }
    int out_size = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &out_size, ad.value().data(),
                          ad.value().size()) != 1) {
      LOG(ERROR) << "Failed to add additional authentication data.";
      return false;
    }
    if (out_size != ad.value().size()) {
      LOG(ERROR) << "Failed to process entire ad.";
      return false;
    }
  }
  brillo::SecureBlob result;
  result.resize(ciphertext.size());
  int output_size = 0;
  if (EVP_DecryptUpdate(ctx.get(), result.data(), &output_size,
                        ciphertext.data(), ciphertext.size()) != 1) {
    LOG(ERROR) << "Failed to decrypt the plaintext.";
    return false;
  }

  if (output_size != ciphertext.size()) {
    LOG(ERROR) << "Failed to process entire ciphertext.";
    return false;
  }

  uint8_t* tag_ptr = const_cast<uint8_t*>(tag.data());
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, tag.size(),
                          tag_ptr) != 1) {
    LOG(ERROR) << "Failed to set the tag.";
    return false;
  }

  output_size = 0;
  int ret_val = EVP_DecryptFinal_ex(ctx.get(), nullptr, &output_size);
  bool success = output_size == 0 && ret_val > 0;
  if (success) {
    *plaintext = result;
  }
  return success;
}

bool AesGcmEncrypt(const brillo::SecureBlob& plaintext,
                   const std::optional<brillo::SecureBlob>& ad,
                   const brillo::SecureBlob& key,
                   brillo::SecureBlob* iv,
                   brillo::SecureBlob* tag,
                   brillo::SecureBlob* ciphertext) {
  if (plaintext.empty()) {
    NOTREACHED() << "Empty plaintext passed to AesGcmEncrypt.";
    return false;
  }
  if (key.size() != kAesGcm256KeySize) {
    NOTREACHED() << "Wrong key size passed to AesGcmEncrypt: " << key.size()
                 << ", expected " << kAesGcm256KeySize << ".";
    return false;
  }

  iv->resize(kAesGcmIVSize);
  GetSecureRandom(iv->data(), kAesGcmIVSize);

  crypto::ScopedEVP_CIPHER_CTX ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    LOG(ERROR) << "Failed to create context.";
    return false;
  }

  if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr,
                         nullptr) != 1) {
    LOG(ERROR) << "Failed to init aes-gcm-256.";
    return false;
  }

  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, kAesGcmIVSize,
                          nullptr) != 1) {
    LOG(ERROR) << "Failed to set IV length.";
    return false;
  }

  if (EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), iv->data()) !=
      1) {
    LOG(ERROR) << "Failed to init key and iv.";
    return false;
  }

  if (ad.has_value()) {
    if (ad.value().empty()) {
      NOTREACHED() << "Empty associated data passed to AesGcmEncrypt.";
      return false;
    }
    int out_size = 0;
    if (EVP_EncryptUpdate(ctx.get(), nullptr, &out_size, ad.value().data(),
                          ad.value().size()) != 1) {
      LOG(ERROR) << "Failed to add additional authentication data.";
      return false;
    }
    if (out_size != ad.value().size()) {
      LOG(ERROR) << "Failed to process entire ad.";
      return false;
    }
  }
  brillo::SecureBlob result;
  result.resize(plaintext.size());
  int processed_bytes = 0;
  if (EVP_EncryptUpdate(ctx.get(), result.data(), &processed_bytes,
                        plaintext.data(), plaintext.size()) != 1) {
    LOG(ERROR) << "Failed to encrypt plaintext.";
    return false;
  }

  if (plaintext.size() != processed_bytes) {
    LOG(ERROR) << "Did not process the entire plaintext.";
    return false;
  }

  int unused_output_length;
  if (EVP_EncryptFinal_ex(ctx.get(), nullptr, &unused_output_length) != 1) {
    LOG(ERROR) << "Failed to finalize encryption.";
    return false;
  }

  tag->resize(kAesGcmTagSize);
  if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, kAesGcmTagSize,
                          tag->data()) != 1) {
    LOG(ERROR) << "Failed to retrieve tag.";
    return false;
  }

  *ciphertext = result;
  return true;
}

// This is the reverse operation of AesEncryptSpecifyBlockMode above.  See that
// method for a description of how padding and block_mode affect the crypto
// operations.  This method automatically removes and verifies the padding, so
// plain_text (on success) will contain the original data.
//
// Note that a call to AesDecryptSpecifyBlockMode needs to have the same padding
// and block_mode as the corresponding encrypt call.  Changing the block mode
// will drastically alter the decryption.  And an incorrect PaddingScheme will
// result in the padding verification failing, for which the method call fails,
// even if the key and initialization vector were correct.
bool AesDecryptSpecifyBlockMode(const brillo::SecureBlob& encrypted,
                                unsigned int start,
                                unsigned int count,
                                const brillo::SecureBlob& key,
                                const brillo::SecureBlob& iv,
                                PaddingScheme padding,
                                BlockMode block_mode,
                                brillo::SecureBlob* plain_text) {
  if ((start > encrypted.size()) || ((start + count) > encrypted.size()) ||
      ((start + count) < start)) {
    return false;
  }
  brillo::SecureBlob local_plain_text(count);

  if (local_plain_text.size() >
      static_cast<unsigned int>(std::numeric_limits<int>::max())) {
    // EVP_DecryptUpdate takes a signed int
    return false;
  }
  int final_size = 0;
  int decrypt_size = local_plain_text.size();

  const EVP_CIPHER* cipher;
  switch (block_mode) {
    case BlockMode::kCbc:
      cipher = EVP_aes_256_cbc();
      break;
    case BlockMode::kEcb:
      cipher = EVP_aes_256_ecb();
      break;
    case BlockMode::kCtr:
      cipher = EVP_aes_256_ctr();
      break;
    default:
      LOG(ERROR) << "Invalid block mode specified: "
                 << static_cast<int>(block_mode);
      return false;
  }
  if (key.size() != static_cast<unsigned int>(EVP_CIPHER_key_length(cipher))) {
    LOG(ERROR) << "Invalid key length of " << key.size() << ", expected "
               << EVP_CIPHER_key_length(cipher);
    return false;
  }
  // ECB ignores the IV, so only check the IV length if we are using a different
  // block mode.
  if ((block_mode != BlockMode::kEcb) &&
      (iv.size() != static_cast<unsigned int>(EVP_CIPHER_iv_length(cipher)))) {
    LOG(ERROR) << "Invalid iv length of " << iv.size() << ", expected "
               << EVP_CIPHER_iv_length(cipher);
    return false;
  }

  crypto::ScopedEVP_CIPHER_CTX decryption_context(EVP_CIPHER_CTX_new());
  if (!decryption_context) {
    LOG(ERROR) << "Failed to allocate EVP_CIPHER_CTX";
    return false;
  }
  EVP_DecryptInit_ex(decryption_context.get(), cipher, nullptr, key.data(),
                     iv.data());
  if (padding == PaddingScheme::kPaddingNone) {
    EVP_CIPHER_CTX_set_padding(decryption_context.get(), 0);
  }

  // Make sure we're not pointing into an empty buffer or past the end.
  const unsigned char* encrypted_buf = NULL;
  if (start < encrypted.size())
    encrypted_buf = &encrypted[start];

  if (!EVP_DecryptUpdate(decryption_context.get(), local_plain_text.data(),
                         &decrypt_size, encrypted_buf, count)) {
    LOG(ERROR) << "DecryptUpdate failed";
    return false;
  }

  // In the case of local_plain_text being full, we must avoid trying to
  // point past the end of the buffer when calling EVP_DecryptFinal_ex().
  unsigned char* final_buf = NULL;
  if (static_cast<unsigned int>(decrypt_size) < local_plain_text.size())
    final_buf = &local_plain_text[decrypt_size];

  if (!EVP_DecryptFinal_ex(decryption_context.get(), final_buf, &final_size)) {
    unsigned long err = ERR_get_error();  // NOLINT openssl types
    ERR_load_ERR_strings();
    ERR_load_crypto_strings();

    LOG(ERROR) << "DecryptFinal Error: " << err << ": "
               << ERR_lib_error_string(err) << ", "
               << ERR_func_error_string(err) << ", "
               << ERR_reason_error_string(err);

    return false;
  }
  final_size += decrypt_size;

  if (padding == PaddingScheme::kPaddingCryptohomeDefaultDeprecated) {
    if (final_size < SHA_DIGEST_LENGTH) {
      LOG(ERROR) << "Plain text was too small.";
      return false;
    }

    final_size -= SHA_DIGEST_LENGTH;

    SHA_CTX sha_context;
    unsigned char md_value[SHA_DIGEST_LENGTH];

    SHA1_Init(&sha_context);
    SHA1_Update(&sha_context, local_plain_text.data(), final_size);
    SHA1_Final(md_value, &sha_context);

    const unsigned char* md_ptr = local_plain_text.data();
    md_ptr += final_size;
    if (brillo::SecureMemcmp(md_ptr, md_value, SHA_DIGEST_LENGTH)) {
      LOG(ERROR) << "Digest verification failed.";
      return false;
    }
  }

  local_plain_text.resize(final_size);
  plain_text->swap(local_plain_text);
  return true;
}

// AesEncryptSpecifyBlockMode encrypts the bytes in plain_text using AES,
// placing the output into encrypted.  Aside from range constraints (start and
// count) and the key and initialization vector, this method has two parameters
// that control how the ciphertext is generated and are useful in encrypting
// specific types of data in hwsec_foundation.
//
// First, padding specifies whether and how the plaintext is padded before
// encryption.  The three options, described in the PaddingScheme enumeration
// are used as such:
//   - PaddingScheme::kPaddingNone is used to mix the user's passkey (derived
//   from the
//     password) into the encrypted blob storing the vault keyset when the TPM
//     is used.  This is described in more detail in the README file.  There is
//     no padding in this case, and the size of plain_text needs to be a
//     multiple of the AES block size (16 bytes).
//   - PaddingScheme::kPaddingStandard uses standard PKCS padding, which is the
//   default for
//     OpenSSL.
//   - PaddingScheme::kPaddingCryptohomeDefaultDeprecated appends a SHA1 hash of
//   the plaintext
//     in plain_text before passing it to OpenSSL, which still uses PKCS padding
//     so that we do not have to re-implement block-multiple padding ourselves.
//     This padding scheme allows us to strongly verify the plaintext on
//     decryption, which is essential when, for example, test decrypting a nonce
//     to test whether a password was correct (we do this in user_session.cc).
//     This padding is now deprecated and a standard integrity checking
//     algorithm such as AES-GCM should be used instead.
//
// The block mode switches between ECB and CBC.  Generally, CBC is used for most
// AES crypto that we perform, since it is a better mode for us for data that is
// larger than the block size.  We use ECB only when mixing the user passkey
// into the TPM-encrypted blob, since we only encrypt a single block of that
// data.
bool AesEncryptSpecifyBlockMode(const brillo::SecureBlob& plain_text,
                                unsigned int start,
                                unsigned int count,
                                const brillo::SecureBlob& key,
                                const brillo::SecureBlob& iv,
                                PaddingScheme padding,
                                BlockMode block_mode,
                                brillo::SecureBlob* encrypted) {
  // Verify that the range is within the data passed
  if ((start > plain_text.size()) || ((start + count) > plain_text.size()) ||
      ((start + count) < start)) {
    return false;
  }
  if (count > static_cast<unsigned int>(std::numeric_limits<int>::max())) {
    // EVP_EncryptUpdate takes a signed int
    return false;
  }

  // First set the output size based on the padding scheme.  No padding means
  // that the input needs to be a multiple of the block size, and the output
  // size is equal to the input size.  Standard padding means we should allocate
  // up to a full block additional for the PKCS padding.  Cryptohome default
  // means we should allocate a full block additional for the PKCS padding and
  // enough for a SHA1 hash.
  unsigned int block_size = GetAesBlockSize();
  unsigned int needed_size = count;
  switch (padding) {
    case PaddingScheme::kPaddingCryptohomeDefaultDeprecated:
      // The AES block size and SHA digest length are not enough for this to
      // overflow, as needed_size is initialized to count, which must be <=
      // INT_MAX, but needed_size is itself an unsigned.  The block size and
      // digest length are fixed by the algorithm.
      needed_size += block_size + SHA_DIGEST_LENGTH;
      break;
    case PaddingScheme::kPaddingStandard:
      needed_size += block_size;
      break;
    case PaddingScheme::kPaddingNone:
      if (count % block_size) {
        LOG(ERROR) << "Data size (" << count << ") was not a multiple "
                   << "of the block size (" << block_size << ")";
        return false;
      }
      break;
    default:
      LOG(ERROR) << "Invalid padding specified";
      return false;
      break;
  }
  brillo::SecureBlob cipher_text(needed_size);

  // Set the block mode
  const EVP_CIPHER* cipher;
  switch (block_mode) {
    case BlockMode::kCbc:
      cipher = EVP_aes_256_cbc();
      break;
    case BlockMode::kEcb:
      cipher = EVP_aes_256_ecb();
      break;
    case BlockMode::kCtr:
      cipher = EVP_aes_256_ctr();
      break;
    default:
      LOG(ERROR) << "Invalid block mode specified";
      return false;
  }
  if (key.size() != static_cast<unsigned int>(EVP_CIPHER_key_length(cipher))) {
    LOG(ERROR) << "Invalid key length of " << key.size() << ", expected "
               << EVP_CIPHER_key_length(cipher);
    return false;
  }

  // ECB ignores the IV, so only check the IV length if we are using a different
  // block mode.
  if ((block_mode != BlockMode::kEcb) &&
      (iv.size() != static_cast<unsigned int>(EVP_CIPHER_iv_length(cipher)))) {
    LOG(ERROR) << "Invalid iv length of " << iv.size() << ", expected "
               << EVP_CIPHER_iv_length(cipher);
    return false;
  }

  // Initialize the OpenSSL crypto context
  crypto::ScopedEVP_CIPHER_CTX encryption_context(EVP_CIPHER_CTX_new());
  if (!encryption_context) {
    LOG(ERROR) << "Failed to allocate EVP_CIPHER_CTX";
    return false;
  }

  EVP_EncryptInit_ex(encryption_context.get(), cipher, nullptr, key.data(),
                     iv.data());
  if (padding == PaddingScheme::kPaddingNone) {
    EVP_CIPHER_CTX_set_padding(encryption_context.get(), 0);
  }

  // First, encrypt the plain_text data
  unsigned int current_size = 0;
  int encrypt_size = 0;

  // Make sure we're not pointing into an empty buffer or past the end.
  const unsigned char* plain_buf = NULL;
  if (start < plain_text.size())
    plain_buf = &plain_text[start];

  if (!EVP_EncryptUpdate(encryption_context.get(), &cipher_text[current_size],
                         &encrypt_size, plain_buf, count)) {
    LOG(ERROR) << "EncryptUpdate failed";
    return false;
  }
  current_size += encrypt_size;
  encrypt_size = 0;

  // Next, if the padding uses the hwsec_foundation default scheme, encrypt a
  // SHA1 hash of the preceding plain_text into the output data
  if (padding == PaddingScheme::kPaddingCryptohomeDefaultDeprecated) {
    SHA_CTX sha_context;
    unsigned char md_value[SHA_DIGEST_LENGTH];

    SHA1_Init(&sha_context);
    SHA1_Update(&sha_context, &plain_text[start], count);
    SHA1_Final(md_value, &sha_context);
    if (!EVP_EncryptUpdate(encryption_context.get(), &cipher_text[current_size],
                           &encrypt_size, md_value, sizeof(md_value))) {
      LOG(ERROR) << "EncryptUpdate failed";
      return false;
    }
    current_size += encrypt_size;
    encrypt_size = 0;
  }

  // In the case of cipher_text being full, we must avoid trying to
  // point past the end of the buffer when calling EVP_EncryptFinal_ex().
  unsigned char* final_buf = NULL;
  if (static_cast<unsigned int>(current_size) < cipher_text.size())
    final_buf = &cipher_text[current_size];

  // Finally, finish the encryption
  if (!EVP_EncryptFinal_ex(encryption_context.get(), final_buf,
                           &encrypt_size)) {
    LOG(ERROR) << "EncryptFinal failed";
    return false;
  }
  current_size += encrypt_size;
  cipher_text.resize(current_size);

  encrypted->swap(cipher_text);
  return true;
}

}  // namespace hwsec_foundation
