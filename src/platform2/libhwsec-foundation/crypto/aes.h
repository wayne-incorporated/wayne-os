// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_CRYPTO_AES_H_
#define LIBHWSEC_FOUNDATION_CRYPTO_AES_H_

#include <optional>

#include <brillo/secure_blob.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

// AES block size in bytes.
inline constexpr unsigned int kAesBlockSize = 16;

// The size of the AES-GCM IV (96-bits).
inline constexpr unsigned int kAesGcmIVSize = 96 / (sizeof(uint8_t) * CHAR_BIT);

// The size of an AES-GCM key in hwsec_foundation code (256-bits).
inline constexpr unsigned int kAesGcm256KeySize =
    256 / (sizeof(uint8_t) * CHAR_BIT);

// The size of the AES-GCM tag.
inline constexpr unsigned int kAesGcmTagSize = 16;

// AES key size in bytes (256-bit).  This key size is used for all key creation,
// though we currently only use 128 bits for the eCryptfs File Encryption Key
// (FEK).  Larger than 128-bit has too great of a CPU overhead on unaccelerated
// architectures.
inline constexpr unsigned int kDefaultAesKeySize = 32;

enum class PaddingScheme {
  kPaddingNone = 0,
  // Also called PKCS padding.
  // See http://tools.ietf.org/html/rfc5652#section-6.3.
  kPaddingStandard = 1,
  kPaddingCryptohomeDefaultDeprecated = 2,
};

enum class BlockMode {
  kEcb = 1,
  kCbc = 2,
  kCtr = 3,
};

// Returns the block size of the AES-256 cipher.
size_t HWSEC_FOUNDATION_EXPORT GetAesBlockSize();

// Derives a key and IV from the password.
//
// Parameters
//   passkey - The data to derive the key from.
//   salt - Used as a salt in the derivation. Must have `PKCS5_SALT_LEN` size.
//   rounds - The iteration count to use.
//            Increasing the `rounds` parameter slows down the algorithm which
//            makes it harder for an attacker to perform a brute force attack
//            using a large number of candidate passwords.
//    key - On success, the derived key.
//    iv - On success, the derived iv.
[[nodiscard]] bool HWSEC_FOUNDATION_EXPORT
PasskeyToAesKey(const brillo::SecureBlob& passkey,
                const brillo::SecureBlob& salt,
                unsigned int rounds,
                brillo::SecureBlob* key,
                brillo::SecureBlob* iv);

// AES encrypts the plain text data using the specified key and IV.  This
// method uses custom padding and is not inter-operable with other crypto
// systems.  The encrypted data can be decrypted with AesDecrypt.
//
// Parameters
//   plaintext - The plain text data to encrypt
//   key - The AES key to use
//   iv - The initialization vector to use
//   ciphertext - On success, the encrypted data
bool HWSEC_FOUNDATION_EXPORT
AesEncryptDeprecated(const brillo::SecureBlob& plaintext,
                     const brillo::SecureBlob& key,
                     const brillo::SecureBlob& iv,
                     brillo::SecureBlob* ciphertext);

// Decrypts data encrypted with AesEncrypt.
//
// Parameters
//   wrapped - The blob containing the encrypted data
//   key - The AES key to use in decryption
//   iv - The initialization vector to use
//   plaintext - The unwrapped (decrypted) data
bool HWSEC_FOUNDATION_EXPORT
AesDecryptDeprecated(const brillo::SecureBlob& ciphertext,
                     const brillo::SecureBlob& key,
                     const brillo::SecureBlob& iv,
                     brillo::SecureBlob* plaintext);

// AES-GCM decrypts the |ciphertext| using the |key| and |iv|. |key| must be
// 256-bits and |iv| must be 96-bits.
//
// Parameters:
//   ciphertext - The encrypted data.
//   ad - (optional) additional authenticated data.
//   tag - The integrity check of the data.
//   key - The key to decrypt with.
//   iv - The IV to decrypt with.
//   plaintext - On success, the decrypted data.
bool HWSEC_FOUNDATION_EXPORT
AesGcmDecrypt(const brillo::SecureBlob& ciphertext,
              const std::optional<brillo::SecureBlob>& ad,
              const brillo::SecureBlob& tag,
              const brillo::SecureBlob& key,
              const brillo::SecureBlob& iv,
              brillo::SecureBlob* plaintext);

// AES-GCM encrypts the |plaintext| using the |key|. A random initialization
// vector is created and retuned in |iv|. The encrypted data can be decrypted
// with AesGcmDecrypt. |key| must be 256-bits.
//
// Parameters:
//   plaintext - The plain text data to encrypt.
//   ad - (optional) additional authenticated data
//   key - The AES key to use.
//   iv - The initialization vector generated randomly.
//   tag - On success, the integrity tag of the data.
//   ciphertext - On success, the encrypted data.
bool HWSEC_FOUNDATION_EXPORT
AesGcmEncrypt(const brillo::SecureBlob& plaintext,
              const std::optional<brillo::SecureBlob>& ad,
              const brillo::SecureBlob& key,
              brillo::SecureBlob* iv,
              brillo::SecureBlob* tag,
              brillo::SecureBlob* ciphertext);

// Same as AesDecrypt, but allows using either CBC or ECB
bool HWSEC_FOUNDATION_EXPORT
AesDecryptSpecifyBlockMode(const brillo::SecureBlob& ciphertext,
                           unsigned int start,
                           unsigned int count,
                           const brillo::SecureBlob& key,
                           const brillo::SecureBlob& iv,
                           PaddingScheme padding,
                           BlockMode mode,
                           brillo::SecureBlob* plaintext);

// Same as AesEncrypt, but allows using either CBC or ECB
bool HWSEC_FOUNDATION_EXPORT
AesEncryptSpecifyBlockMode(const brillo::SecureBlob& plaintext,
                           unsigned int start,
                           unsigned int count,
                           const brillo::SecureBlob& key,
                           const brillo::SecureBlob& iv,
                           PaddingScheme padding,
                           BlockMode mode,
                           brillo::SecureBlob* ciphertext);
}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_CRYPTO_AES_H_
