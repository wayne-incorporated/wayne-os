// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/rsa.h"

#include <iterator>
#include <utility>
#include <openssl/err.h>

#include <base/check.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <crypto/scoped_openssl_types.h>

#include "libhwsec-foundation/crypto/aes.h"
#include "libhwsec-foundation/crypto/sha.h"

namespace hwsec_foundation {

bool CreateRsaKey(size_t key_bits,
                  brillo::SecureBlob* n,
                  brillo::SecureBlob* p) {
  crypto::ScopedRSA rsa(RSA_new());
  crypto::ScopedBIGNUM e(BN_new());
  if (!rsa || !e) {
    LOG(ERROR) << "Failed to allocate RSA or BIGNUM.";
    return false;
  }
  if (!BN_set_word(e.get(), kWellKnownExponent) ||
      !RSA_generate_key_ex(rsa.get(), key_bits, e.get(), nullptr)) {
    LOG(ERROR) << "RSA key generation failed.";
    return false;
  }

  brillo::SecureBlob local_n(RSA_size(rsa.get()));
  const BIGNUM* rsa_n;
  RSA_get0_key(rsa.get(), &rsa_n, nullptr, nullptr);
  if (BN_bn2bin(rsa_n, local_n.data()) <= 0) {
    LOG(ERROR) << "Unable to get modulus from RSA key.";
    return false;
  }

  const BIGNUM* rsa_p;
  RSA_get0_factors(rsa.get(), &rsa_p, nullptr);
  brillo::SecureBlob local_p(BN_num_bytes(rsa_p));
  if (BN_bn2bin(rsa_p, local_p.data()) <= 0) {
    LOG(ERROR) << "Unable to get private key from RSA key.";
    return false;
  }

  n->swap(local_n);
  p->swap(local_p);
  return true;
}

bool FillRsaPrivateKeyFromSecretPrime(const brillo::SecureBlob& secret_prime,
                                      RSA* rsa) {
  crypto::ScopedOpenSSL<BN_CTX, BN_CTX_free> bn_context(BN_CTX_new());
  if (!bn_context) {
    LOG(ERROR) << "Failed to allocate BN_CTX structure";
    return false;
  }
  // Load the first prime from the parameter.
  crypto::ScopedBIGNUM p(BN_new()), q(BN_new()), remainder(BN_new());
  if (!p || !q || !remainder) {
    LOG(ERROR) << "Failed to allocate BIGNUM structure";
    return false;
  }

  if (!BN_bin2bn(secret_prime.data(), secret_prime.size(), p.get())) {
    LOG(ERROR) << "Failed to construct secret prime from binary blob";
    return false;
  }
  // Calculate the second prime by dividing the public modulus.
  const BIGNUM* rsa_n;
  const BIGNUM* rsa_e;
  RSA_get0_key(rsa, &rsa_n, &rsa_e, nullptr);
  if (!BN_div(q.get(), remainder.get(), rsa_n, p.get(), bn_context.get())) {
    LOG(ERROR) << "Failed to divide public modulus";
    return false;
  }
  if (!BN_is_zero(remainder.get())) {
    LOG(ERROR) << "Bad secret prime: does not divide the modulus evenly";
    return false;
  }

  // Calculate the private exponent.
  crypto::ScopedBIGNUM d(BN_new());
  crypto::ScopedBIGNUM decremented_p(BN_new());
  crypto::ScopedBIGNUM decremented_q(BN_new());
  crypto::ScopedBIGNUM totient(BN_new());
  if (!d || !decremented_p || !decremented_q || !totient) {
    LOG(ERROR) << "Failed to allocate BIGNUM structure";
    return false;
  }
  if (!BN_sub(decremented_p.get(), p.get(), BN_value_one()) ||
      !BN_sub(decremented_q.get(), q.get(), BN_value_one()) ||
      !BN_mul(totient.get(), decremented_p.get(), decremented_q.get(),
              bn_context.get())) {
    LOG(ERROR) << "Failed to calculate totient function";
    return false;
  }
  if (!BN_mod_inverse(d.get(), rsa_e, totient.get(), bn_context.get())) {
    LOG(ERROR) << "Failed to calculate modular inverse";
    return false;
  }

  // Calculate the private exponent modulo the decremented first and second
  // primes.
  crypto::ScopedBIGNUM dmp1(BN_new()), dmq1(BN_new()), iqmp(BN_new());
  if (!dmp1 || !dmq1 || !iqmp) {
    LOG(ERROR) << "Failed to allocate BIGNUM structure";
    return false;
  }
  if (!BN_mod(dmp1.get(), d.get(), decremented_p.get(), bn_context.get()) ||
      !BN_mod(dmq1.get(), d.get(), decremented_q.get(), bn_context.get())) {
    LOG(ERROR) << "Failed to calculate the private exponent over the modulo";
    return false;
  }
  // Calculate the inverse of the second prime modulo the first prime.
  if (!BN_mod_inverse(iqmp.get(), q.get(), p.get(), bn_context.get())) {
    LOG(ERROR) << "Failed to calculate the inverse of the prime module the "
                  "other prime";
    return false;
  }

  // All checks pass, now assign fields
  if (!RSA_set0_factors(rsa, p.release(), q.release()) ||
      !RSA_set0_key(rsa, nullptr, nullptr, d.release()) ||
      !RSA_set0_crt_params(rsa, dmp1.release(), dmq1.release(),
                           iqmp.release())) {
    LOG(ERROR) << "Failed to set RSA parameters.";
    return false;
  }
  return true;
}

// Obscure (and Unobscure) RSA messages.
// Let k be a key derived from the user passphrase. On disk, we store
// m = ObscureRsaMessage(RSA-on-TPM(random-data), k). The reason for this
// function is the existence of an ambiguity in the TPM spec: the format of data
// returned by Tspi_Data_Bind is unspecified, so it's _possible_ (although does
// not happen in practice) that RSA-on-TPM(random-data) could start with some
// kind of ASN.1 header or whatever (some known data). If this was true, and we
// encrypted all of RSA-on-TPM(random-data), then one could test values of k by
// decrypting RSA-on-TPM(random-data) and looking for the known header, which
// would allow brute-forcing the user passphrase without talking to the TPM.
//
// Therefore, we instead encrypt _one block_ of RSA-on-TPM(random-data) with AES
// in ECB mode; we pick the last AES block, in the hope that that block will be
// part of the RSA message. TODO(ellyjones): why? if the TPM could add a header,
// it could also add a footer, and we'd be just as sunk.
//
// If we do encrypt part of the RSA message, the entirety of
// RSA-on-TPM(random-data) should be impossible to decrypt, without encrypting
// any known plaintext. This approach also requires brute-force attempts on k to
// go through the TPM, since there's no way to test a potential decryption
// without doing UnRSA-on-TPM() to see if the message is valid now.
bool ObscureRsaMessage(const brillo::SecureBlob& plaintext,
                       const brillo::SecureBlob& key,
                       brillo::SecureBlob* ciphertext) {
  unsigned int aes_block_size = GetAesBlockSize();
  if (plaintext.size() < aes_block_size * 2) {
    LOG(ERROR) << "Plaintext is too small.";
    return false;
  }
  unsigned int offset = plaintext.size() - aes_block_size;

  brillo::SecureBlob obscured_chunk;
  if (!AesEncryptSpecifyBlockMode(
          plaintext, offset, aes_block_size, key, brillo::SecureBlob(0),
          PaddingScheme::kPaddingNone, BlockMode::kEcb, &obscured_chunk)) {
    LOG(ERROR) << "AES encryption failed.";
    return false;
  }
  ciphertext->resize(plaintext.size());
  char* data = reinterpret_cast<char*>(ciphertext->data());
  memcpy(data, plaintext.data(), plaintext.size());
  memcpy(data + offset, obscured_chunk.data(), obscured_chunk.size());
  return true;
}

bool UnobscureRsaMessage(const brillo::SecureBlob& ciphertext,
                         const brillo::SecureBlob& key,
                         brillo::SecureBlob* plaintext) {
  unsigned int aes_block_size = GetAesBlockSize();
  if (ciphertext.size() < aes_block_size * 2) {
    LOG(ERROR) << "Ciphertext is is too small.";
    return false;
  }
  unsigned int offset = ciphertext.size() - aes_block_size;

  brillo::SecureBlob unobscured_chunk;
  if (!AesDecryptSpecifyBlockMode(
          ciphertext, offset, aes_block_size, key, brillo::SecureBlob(0),
          PaddingScheme::kPaddingNone, BlockMode::kEcb, &unobscured_chunk)) {
    LOG(ERROR) << "AES decryption failed.";
    return false;
  }
  plaintext->resize(ciphertext.size());
  char* data = reinterpret_cast<char*>(plaintext->data());
  memcpy(data, ciphertext.data(), ciphertext.size());
  memcpy(data + offset, unobscured_chunk.data(), unobscured_chunk.size());
  return true;
}

bool RsaOaepEncrypt(const brillo::SecureBlob& plaintext,
                    RSA* key,
                    brillo::Blob* ciphertext) {
  if (plaintext.empty())
    return false;
  ciphertext->resize(RSA_size(key));
  const int encryption_result =
      RSA_public_encrypt(plaintext.size(), plaintext.data(), ciphertext->data(),
                         key, RSA_PKCS1_OAEP_PADDING);
  if (encryption_result == -1) {
    LOG(ERROR) << "Failed to perform RSAES-OAEP MGF1 encryption";
    return false;
  }
  if (encryption_result != ciphertext->size()) {
    NOTREACHED()
        << "RSAES-OAEP MGF1 encryption returned unexpected amount of data";
    return false;
  }
  return true;
}

bool RsaOaepDecrypt(const brillo::SecureBlob& ciphertext,
                    const brillo::SecureBlob& oaep_label,
                    RSA* key,
                    brillo::SecureBlob* plaintext) {
  const int key_size = RSA_size(key);
  brillo::SecureBlob raw_decrypted_data(key_size);
  const int decryption_result =
      RSA_private_decrypt(ciphertext.size(), ciphertext.data(),
                          raw_decrypted_data.data(), key, RSA_NO_PADDING);
  if (decryption_result == -1) {
    LOG(ERROR) << "RSA raw decryption failed: "
               << ERR_error_string(ERR_get_error(), nullptr);
    return false;
  }
  if (decryption_result != key_size) {
    LOG(ERROR) << "RSA raw decryption returned too few data";
    return false;
  }
  brillo::SecureBlob local_plaintext(key_size);
  const int padding_check_result = RSA_padding_check_PKCS1_OAEP(
      local_plaintext.data(), local_plaintext.size(), raw_decrypted_data.data(),
      raw_decrypted_data.size(), key_size, oaep_label.data(),
      oaep_label.size());
  if (padding_check_result == -1) {
    LOG(ERROR)
        << "Failed to perform RSA OAEP decoding of the raw decrypted data";
    return false;
  }
  local_plaintext.resize(padding_check_result);
  *plaintext = std::move(local_plaintext);
  return true;
}

bool VerifyRsaSignatureSha256(const brillo::SecureBlob& input_data,
                              const brillo::SecureBlob& signature,
                              const brillo::SecureBlob& public_key_spki_der) {
  const brillo::SecureBlob digest = Sha256(input_data);

  const unsigned char* public_key_data = public_key_spki_der.data();
  crypto::ScopedRSA rsa(d2i_RSA_PUBKEY(/*RSA=*/nullptr, &public_key_data,
                                       public_key_spki_der.size()));
  if (!rsa.get()) {
    LOG(ERROR)
        << "Failed to decode public key SubjectPublicKeyInfo into an RSA key.";
    return false;
  }

  if (!RSA_verify(NID_sha256, digest.data(), digest.size(), signature.data(),
                  signature.size(), rsa.get())) {
    LOG(ERROR) << "Failed to verify RSA signature.";
    return false;
  }
  return true;
}

bool TpmCompatibleOAEPEncrypt(RSA* key,
                              const brillo::SecureBlob& input,
                              brillo::SecureBlob* output) {
  CHECK(output);

  // The custom OAEP parameter as specified in TPM Main Part 1, Section 31.1.1.
  const unsigned char oaep_param[4] = {'T', 'C', 'P', 'A'};
  brillo::SecureBlob padded_input(RSA_size(key));
  unsigned char* padded_buffer = padded_input.data();
  const unsigned char* input_buffer = input.data();
  int result = RSA_padding_add_PKCS1_OAEP(padded_buffer, padded_input.size(),
                                          input_buffer, input.size(),
                                          oaep_param, std::size(oaep_param));
  if (!result) {
    LOG(ERROR) << "Failed to add OAEP padding.";
    return false;
  }

  output->resize(padded_input.size());
  unsigned char* output_buffer = output->data();
  result = RSA_public_encrypt(padded_input.size(), padded_buffer, output_buffer,
                              key, RSA_NO_PADDING);
  if (result == -1) {
    LOG(ERROR) << "Failed to encrypt OAEP padded input.";
    return false;
  }

  return true;
}

// Checks an RSA key modulus for the ROCA fingerprint (i.e. whether the RSA
// modulus has a discrete logarithm modulus small primes). See research paper
// for details: https://crocs.fi.muni.cz/public/papers/rsa_ccs17
bool TestRocaVulnerable(const BIGNUM* rsa_modulus) {
  const BN_ULONG kPrimes[] = {
      3,   5,   7,   11,  13,  17,  19,  23,  29,  31,  37,  41,  43,  47,
      53,  59,  61,  67,  71,  73,  79,  83,  89,  97,  101, 103, 107, 109,
      113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
  };

  for (BN_ULONG prime : kPrimes) {
    BN_ULONG remainder = BN_mod_word(rsa_modulus, prime);

    // Enumerate all elements F4 generates in the small |prime| subgroup and
    // check whether |remainder| is among them.
    BN_ULONG power = 1;
    do {
      power = (power * 65537) % prime;
    } while (power != 1 && power != remainder);

    // No discrete logarithm -> modulus isn't of the ROCA form and thus not
    // vulnerable.
    if (power != remainder) {
      return false;
    }
  }

  // Discrete logarithms exist for all small primes -> vulnerable with
  // negligible chance of false positive result.
  return true;
}

}  // namespace hwsec_foundation
