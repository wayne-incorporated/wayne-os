// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_CRYPTO_RSA_H_
#define LIBHWSEC_FOUNDATION_CRYPTO_RSA_H_

#include <brillo/secure_blob.h>
#include <openssl/rsa.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"

namespace hwsec_foundation {

// The well-known exponent used when generating RSA keys. Cryptohome only
// generates one RSA key, which is the system-wide cryptohome key. This is the
// common public exponent.
inline constexpr unsigned int kWellKnownExponent = 65537;

// Generates an RSA key pair. The modulus size will be of length |key_bits|, and
// the public exponent will be |kWellKnownExponent|.
// Parameters
//   key_bits - the modulus size.
//   n - the modulus common to both public and private RSA keys.
//   p - first prime factor of the RSA key.
bool HWSEC_FOUNDATION_EXPORT CreateRsaKey(size_t key_bits,
                                          brillo::SecureBlob* n,
                                          brillo::SecureBlob* p);

// Fills out all fields related to the RSA private key information, given the
// public key information provided via |rsa| and the secret prime via
// |secret_prime|.
bool HWSEC_FOUNDATION_EXPORT FillRsaPrivateKeyFromSecretPrime(
    const brillo::SecureBlob& secret_prime, RSA* rsa);

// Obscure an RSA message by encrypting part of it.
// The TPM could _in theory_ produce an RSA message (as a response from Bind)
// that contains a header of a known format. If it did, and we encrypted the
// whole message with a passphrase-derived AES key, then one could test
// passphrase correctness by trial-decrypting the header. Instead, encrypt
// only part of the message, and hope the part we encrypt is part of the RSA
// message.
//
// In practice, this never makes any difference, because no TPM does that; the
// result is always a bare PKCS1.5-padded RSA-encrypted message, which is
// (as far as the author knows, although no proof is known) indistinguishable
// from random data, and hence the attack this would protect against is
// infeasible.
bool HWSEC_FOUNDATION_EXPORT
ObscureRsaMessage(const brillo::SecureBlob& plaintext,
                  const brillo::SecureBlob& key,
                  brillo::SecureBlob* ciphertext);
bool HWSEC_FOUNDATION_EXPORT
UnobscureRsaMessage(const brillo::SecureBlob& ciphertext,
                    const brillo::SecureBlob& key,
                    brillo::SecureBlob* plaintext);

// Encrypts data using the RSA OAEP scheme with the SHA-1 hash function, the
// MGF1 mask function, and an empty label parameter.
bool HWSEC_FOUNDATION_EXPORT RsaOaepEncrypt(const brillo::SecureBlob& plaintext,
                                            RSA* key,
                                            brillo::Blob* ciphertext);

// Decrypts the data encrypted with RSA OAEP with the SHA-1 hash function, the
// MGF1 mask function, and the label parameter equal to |oaep_label|.
bool HWSEC_FOUNDATION_EXPORT
RsaOaepDecrypt(const brillo::SecureBlob& ciphertext,
               const brillo::SecureBlob& oaep_label,
               RSA* key,
               brillo::SecureBlob* plaintext);

// Verify the signature with the SHA-256 hash function. The signature is signed
// using the provided input_data and a private key, of which the corresponding
// public key (DER-encoded X.509 SubjectPublicKeyInfo structure) is provided.
bool HWSEC_FOUNDATION_EXPORT
VerifyRsaSignatureSha256(const brillo::SecureBlob& input_data,
                         const brillo::SecureBlob& signature,
                         const brillo::SecureBlob& public_key_spki_der);

// Encrypts data using the TPM_ES_RSAESOAEP_SHA1_MGF1 scheme.
//
// Parameters
//   key - The RSA public key.
//   input - The data to be encrypted.
//   output - The encrypted data.
bool HWSEC_FOUNDATION_EXPORT TpmCompatibleOAEPEncrypt(
    RSA* key, const brillo::SecureBlob& input, brillo::SecureBlob* output);

// Checks an RSA key modulus for the ROCA fingerprint (i.e. whether the RSA
// modulus has a discrete logarithm modulus small primes). See research paper
// for details: https://crocs.fi.muni.cz/public/papers/rsa_ccs17
bool HWSEC_FOUNDATION_EXPORT TestRocaVulnerable(const BIGNUM* rsa_modulus);

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_CRYPTO_RSA_H_
