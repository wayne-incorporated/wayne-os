// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec/backend/tpm1/static_utils.h"

#include <cinttypes>
#include <cstdint>
#include <iterator>
#include <memory>
#include <utility>

#include <base/check_op.h>
#include <base/memory/free_deleter.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/crypto/secure_blob_util.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/status/status_chain_macros.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>

#include "libhwsec/error/tpm1_error.h"
#include "libhwsec/overalls/overalls.h"
#include "libhwsec/status.h"

using brillo::Blob;
using brillo::BlobFromString;
using brillo::BlobToString;
using brillo::SecureBlob;
using hwsec_foundation::FillRsaPrivateKeyFromSecretPrime;
using hwsec_foundation::kWellKnownExponent;
using hwsec_foundation::RsaOaepDecrypt;
using hwsec_foundation::Sha1;
using hwsec_foundation::status::MakeStatus;

using ScopedByteArray = std::unique_ptr<BYTE, base::FreeDeleter>;

namespace hwsec {

namespace {

// Scoped wrapper of the TPM_KEY12 struct.
class ScopedKey12 final {
 public:
  ScopedKey12() { memset(&value_, 0, sizeof(TPM_KEY12)); }
  ScopedKey12(const ScopedKey12&) = delete;
  ScopedKey12& operator=(const ScopedKey12&) = delete;

  ~ScopedKey12() {
    free(value_.algorithmParms.parms);
    free(value_.pubKey.key);
    free(value_.encData);
    free(value_.PCRInfo);
  }

  const TPM_KEY12& operator*() const { return value_; }
  const TPM_KEY12* operator->() const { return &value_; }
  TPM_KEY12* ptr() { return &value_; }

 private:
  TPM_KEY12 value_;
};

// Parses the TPM_KEY12 blob and returns its "encData" field blob.
StatusOr<Blob> ParseEncDataFromKey12Blob(overalls::Overalls& overalls,
                                         Blob key12_blob) {
  ScopedKey12 key12;
  uint64_t key12_parsing_offset = 0;

  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Orspi_UnloadBlob_KEY12_s(
                      &key12_parsing_offset, key12_blob.data(),
                      key12_blob.size(), key12.ptr())))
      .WithStatus<TPMError>("Failed to call Trspi_UnloadBlob_KEY12_s");

  if (key12_parsing_offset != key12_blob.size()) {
    return MakeStatus<TPMError>(
        "Failed to parse the migrated key TPM_KEY12 blob due to size mismatch",
        TPMRetryAction::kNoRetry);
  }

  Blob enc_data(key12->encData, key12->encData + key12->encSize);
  return enc_data;
}

// Applies to the given blob the element-to-element bitwise XOR against the
// other blob.
void XorBytes(uint8_t* inplace_target_begin,
              const uint8_t* other_begin,
              size_t size) {
  for (size_t index = 0; index < size; ++index)
    inplace_target_begin[index] ^= other_begin[index];
}

// Obtains the value from its MGF1-masked representation in |masked_value|. The
// input value for the MGF1 mask is passed via |mgf_input_value|. Returns the
// result; its length, on success, is guaranteed to be the same as
// the |masked_value|'s one.
StatusOr<SecureBlob> UnmaskWithMgf1(overalls::Overalls& overalls,
                                    SecureBlob masked_value,
                                    SecureBlob mgf_input_value) {
  if (masked_value.empty()) {
    return MakeStatus<TPMError>("Bad MGF1-masked value",
                                TPMRetryAction::kNoRetry);
  }
  if (mgf_input_value.empty()) {
    return MakeStatus<TPMError>("Bad MGF1 input value",
                                TPMRetryAction::kNoRetry);
  }

  SecureBlob mask(masked_value.size());
  RETURN_IF_ERROR(MakeStatus<TPM1Error>(overalls.Orspi_MGF1(
                      TSS_HASH_SHA1, mgf_input_value.size(),
                      mgf_input_value.data(), mask.size(), mask.data())))
      .WithStatus<TPMError>("Failed to call Orspi_MGF1");

  XorBytes(masked_value.data(), mask.data(), masked_value.size());
  return masked_value;
}

struct DecodeOaepMgf1EncodingResult {
  // The OAEP seed.
  SecureBlob seed;

  // The decoded message.
  SecureBlob message;
};

// Performs the RSA OAEP MGF1 decoding of the encoded blob |encoded_blob| using
// the OAEP label parameter equal to |oaep_label|. The size |message_length|
// specifies the expected size of the returned message.
// Returns  DecodeOaepMgf1EncodingResult.
// Note that this custom implementation is used instead of the one from OpenSSL,
// because we need to get the seed back and OpenSSL doesn't return it.
StatusOr<DecodeOaepMgf1EncodingResult> DecodeOaepMgf1Encoding(
    overalls::Overalls& overalls,
    const Blob& encoded_blob,
    size_t message_length,
    const Blob& oaep_label) {
  // The comments in this function below refer to the notation that corresponds
  // to the "RSAES-OAEP Encryption Scheme" Algorithm specification and
  // supporting documentation (2000), the "EME-OAEP-Decode" section.
  // The correspondence between the function parameters and the terms in the
  // specification is:
  // * |encoded_blob| - "EM";
  // * |message_length| - "mLen";
  // * |oaep_label| - "P";
  // * |seed| - "seed";
  // * |message| - "M".
  // Note that as the MGF1 mask is used which is based on SHA-1, the "hLen" term
  // corresponds to |SHA_DIGEST_LENGTH|.
  const size_t blob_size = encoded_blob.size();
  // Step #1 is omitted as not applicable to our implementation - the length of
  // |oaep_label| can't realistically reach the size constraint of SHA-1.
  // Step #2. The total length of the encoded message is formed by the length of
  // "seed" (which is equal to "hLen"), the length of "pHash" (which is also
  // equal to "hLen"), the length of the original message, and the length of the
  // "01" octet (which is 1 byte).
  const size_t minimum_blob_size = 2 * SHA_DIGEST_LENGTH + 1 + message_length;
  if (blob_size < minimum_blob_size) {
    return MakeStatus<TPMError>("Size is too small", TPMRetryAction::kNoRetry);
  }
  // Step #3. Split "EM" into "maskedSeed" and "maskedDB".
  const SecureBlob masked_seed(encoded_blob.begin(),
                               encoded_blob.begin() + SHA_DIGEST_LENGTH);
  const SecureBlob masked_padded_message(
      encoded_blob.begin() + SHA_DIGEST_LENGTH, encoded_blob.end());
  // Steps ##4-5. Unmask "maskedSeed" to obtain "seed".
  ASSIGN_OR_RETURN(const SecureBlob& seed,
                   UnmaskWithMgf1(overalls, masked_seed, masked_padded_message),
                   _.WithStatus<TPMError>("Failed to unmask the seed"));

  // Steps ##6-7. Unmask "maskedDB" into "DB".
  ASSIGN_OR_RETURN(const SecureBlob& padded_message,
                   UnmaskWithMgf1(overalls, masked_padded_message, seed),
                   _.WithStatus<TPMError>("Failed to unmask the message"));

  // Steps ##8-10. Extract "M" from "DB", extract "pHash" from "DB" and check it
  // against "P", and verify the zeros/ones padding that covers the rest.
  const Blob obtained_label_digest(padded_message.begin(),
                                   padded_message.begin() + SHA_DIGEST_LENGTH);
  const Blob obtained_zeroes_ones_padding(
      padded_message.begin() + SHA_DIGEST_LENGTH,
      padded_message.end() - message_length);

  SecureBlob message(padded_message.end() - message_length,
                     padded_message.end());
  DCHECK_EQ(padded_message.size(), obtained_label_digest.size() +
                                       obtained_zeroes_ones_padding.size() +
                                       message.size());

  if (obtained_label_digest != Sha1(oaep_label)) {
    return MakeStatus<TPMError>("Incorrect OAEP label",
                                TPMRetryAction::kNoRetry);
  }
  const Blob expected_zeroes_ones_padding = brillo::CombineBlobs(
      {Blob(obtained_zeroes_ones_padding.size() - 1), Blob(1, 1)});
  if (obtained_zeroes_ones_padding != expected_zeroes_ones_padding) {
    return MakeStatus<TPMError>("Incorrect zeroes block in OAEP padding",
                                TPMRetryAction::kNoRetry);
  }

  return DecodeOaepMgf1EncodingResult{
      .seed = seed,
      .message = message,
  };
}

// Parses an unsigned four-byte integer from the given position in the blob in
// the TPM endianness.
uint32_t DecodeTpmUint32(const uint8_t* begin) {
  UINT64 parsing_offset = 0;
  uint32_t result = 0;
  Trspi_UnloadBlob_UINT32(&parsing_offset, &result, const_cast<BYTE*>(begin));
  DCHECK_EQ(4, parsing_offset);
  return result;
}

// Parses the RSA secret prime from the TPM_MIGRATE_ASYMKEY blob and the seed
// blob.
StatusOr<SecureBlob> ParseRsaSecretPrimeFromTpmMigrateAsymkeyBlob(
    const SecureBlob& tpm_migrate_asymkey_blob,
    const SecureBlob& tpm_migrate_asymkey_oaep_seed_blob) {
  if (tpm_migrate_asymkey_oaep_seed_blob.size() != SHA_DIGEST_LENGTH) {
    return MakeStatus<TPMError>("Wrong migrated asymkey OAEP key size",
                                TPMRetryAction::kNoRetry);
  }

  // The binary layout, as specified in TPM 1.2 Part 3 Section 11.9
  // ("TPM_CMK_CreateBlob"), is:
  // * |tpm_migrate_asymkey_oaep_seed_blob| (called "K1" in the specification):
  //   is of |SHA_DIGEST_LENGTH| bytes length, and is structured as following:
  //   * the first 4 bytes contain a four-byte integer - the size of the private
  //     key in bytes (obtained from TPM_STORE_PRIVKEY.keyLength);
  //   * the rest are the first |kMigratedCmkPrivateKeySeedPartSizeBytes| bytes
  //     of the private key;
  // * |tpm_migrate_asymkey_blob| (called "M1" in the specification): the binary
  //   dump of the TPM_MIGRATE_ASYMKEY structure, of which we are looking only
  //   at:
  //   * the first field |payload| of length 1 byte, which has to be equal to
  //     |TPM_PT_CMK_MIGRATE|;
  //   * the last field |partPrivKey|, which contains the last
  //     |kMigratedCmkPrivateKeyRestPartSizeBytes| bytes of the private key;
  //   * the last but one field |partPrivKeyLen| of length 4 bytes, which is a
  //     four-byte integer that has to be equal to
  //     |kMigratedCmkPrivateKeyRestPartSizeBytes|.
  // We parse and validate this data below:
  // Parse and validate the keyLength field of the TPM_STORE_PRIVKEY structure.
  const uint32_t tpm_store_privkey_key_length =
      DecodeTpmUint32(tpm_migrate_asymkey_oaep_seed_blob.data());
  if (tpm_store_privkey_key_length != kCmkPrivateKeySizeBytes) {
    return MakeStatus<TPMError>("Wrong migrated private key size",
                                TPMRetryAction::kNoRetry);
  }

  // Extract the part of the private key from the OAEP seed.
  const SecureBlob tpm_store_privkey_key_seed_part_blob(
      tpm_migrate_asymkey_oaep_seed_blob.begin() + 4,
      tpm_migrate_asymkey_oaep_seed_blob.end());
  DCHECK_EQ(kMigratedCmkPrivateKeySeedPartSizeBytes,
            tpm_store_privkey_key_seed_part_blob.size());

  // Validate the TPM_MIGRATE_ASYMKEY blob size.
  if (tpm_migrate_asymkey_blob.size() <
      kMigratedCmkPrivateKeyRestPartSizeBytes + 4) {
    return MakeStatus<TPMError>("Wrong migrated private key size",
                                TPMRetryAction::kNoRetry);
  }

  // Parse and validate the payload field of the TPM_MIGRATE_ASYMKEY structure.
  const int tpm_migrate_asymkey_payload = tpm_migrate_asymkey_blob[0];
  if (tpm_migrate_asymkey_payload != TPM_PT_CMK_MIGRATE) {
    return MakeStatus<TPMError>("Wrong migration payload type",
                                TPMRetryAction::kNoRetry);
  }
  // Extract the part of the private key from the TPM_MIGRATE_ASYMKEY blob.
  const SecureBlob tpm_store_privkey_key_rest_part_blob(
      tpm_migrate_asymkey_blob.end() - kMigratedCmkPrivateKeyRestPartSizeBytes,
      tpm_migrate_asymkey_blob.end());
  // Parse and validate the partPrivKeyLen field of the TPM_MIGRATE_ASYMKEY
  // structure.
  const uint32_t tpm_migrate_asymkey_part_priv_key_length = DecodeTpmUint32(
      &tpm_migrate_asymkey_blob[tpm_migrate_asymkey_blob.size() -
                                kMigratedCmkPrivateKeyRestPartSizeBytes - 4]);
  if (tpm_migrate_asymkey_part_priv_key_length !=
      kMigratedCmkPrivateKeyRestPartSizeBytes) {
    return MakeStatus<TPMError>(
        "Wrong size of the private key part in TPM_MIGRATE_ASYMKEY",
        TPMRetryAction::kNoRetry);
  }

  // Assemble the resulting secret prime blob.
  SecureBlob secret_prime_blob =
      SecureBlob::Combine(tpm_store_privkey_key_seed_part_blob,
                          tpm_store_privkey_key_rest_part_blob);
  DCHECK_EQ(kCmkPrivateKeySizeBytes, secret_prime_blob.size());

  return secret_prime_blob;
}

}  // namespace

StatusOr<crypto::ScopedRSA> ParseRsaFromTpmPubkeyBlob(
    overalls::Overalls& overalls, const brillo::Blob& pubkey) {
  // Parse the serialized TPM_PUBKEY.
  brillo::Blob pubkey_copy = pubkey;
  uint64_t offset = 0;
  TPM_PUBKEY parsed = {};  // Zero initialize.

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Orspi_UnloadBlob_PUBKEY_s(
          &offset, pubkey_copy.data(), pubkey_copy.size(), &parsed)))
      .WithStatus<TPMError>("Failed to call Orspi_UnloadBlob_PUBKEY_s");

  ScopedByteArray scoped_key(parsed.pubKey.key);
  ScopedByteArray scoped_parms(parsed.algorithmParms.parms);

  if (offset != pubkey.size()) {
    return MakeStatus<TPMError>("Found garbage data after the TPM_PUBKEY",
                                TPMRetryAction::kNoRetry);
  }

  uint64_t parms_offset = 0;
  TPM_RSA_KEY_PARMS parms = {};  // Zero initialize.

  RETURN_IF_ERROR(
      MakeStatus<TPM1Error>(overalls.Orspi_UnloadBlob_RSA_KEY_PARMS_s(
          &parms_offset, parsed.algorithmParms.parms,
          parsed.algorithmParms.parmSize, &parms)))
      .WithStatus<TPMError>("Failed to call Orspi_UnloadBlob_RSA_KEY_PARMS_s");

  ScopedByteArray scoped_exponent(parms.exponent);

  if (parms_offset != parsed.algorithmParms.parmSize) {
    return MakeStatus<TPMError>(
        "Found garbage data after the TPM_PUBKEY algorithm params",
        TPMRetryAction::kNoRetry);
  }

  // Get the public exponent.
  crypto::ScopedRSA rsa(RSA_new());
  crypto::ScopedBIGNUM e(BN_new()), n(BN_new());
  if (!rsa || !e || !n) {
    return MakeStatus<TPMError>("Failed to create RSA or BIGNUM",
                                TPMRetryAction::kNoRetry);
  }
  if (!parms.exponentSize) {
    if (!BN_set_word(e.get(), kWellKnownExponent)) {
      return MakeStatus<TPMError>(
          "Failed to set BN exponent to WellKnownExponent",
          TPMRetryAction::kNoRetry);
    }
  } else {
    if (!BN_bin2bn(parms.exponent, parms.exponentSize, e.get())) {
      return MakeStatus<TPMError>("Failed to load BN exponent from TPM_PUBKEY",
                                  TPMRetryAction::kNoRetry);
    }
  }

  // Get the modulus.
  if (!BN_bin2bn(parsed.pubKey.key, parsed.pubKey.keyLength, n.get())) {
    return MakeStatus<TPMError>("Failed to load BN modulus from TPM_PUBKEY",
                                TPMRetryAction::kNoRetry);
  }

  if (!RSA_set0_key(rsa.get(), n.release(), e.release(), nullptr)) {
    return MakeStatus<TPMError>("Failed to set parameters for RSA",
                                TPMRetryAction::kNoRetry);
  }

  return rsa;
}

StatusOr<crypto::ScopedRSA> ExtractCmkPrivateKeyFromMigratedBlob(
    overalls::Overalls& overalls,
    const Blob& migrated_cmk_key12_blob,
    const Blob& migration_random_blob,
    const Blob& cmk_pubkey,
    const Blob& cmk_pubkey_digest,
    const Blob& msa_composite_digest,
    RSA& migration_destination_rsa) {
  // Load the encrypted TPM_MIGRATE_ASYMKEY blob from the TPM_KEY12 blob.
  // Note that this encrypted TPM_MIGRATE_ASYMKEY blob was generated by taking
  // the TPM_MIGRATE_ASYMKEY blob, applying the RSA OAEP *encoding* (not
  // encryption), XOR'ing it with the migration random XOR-mask, applying the
  // RSA OAEP *encryption* (not encoding). We'll unwind this to obtain the
  // original TPM_MIGRATE_ASYMKEY blob below.
  ASSIGN_OR_RETURN(const Blob& encrypted_tpm_migrate_asymkey_blob,
                   ParseEncDataFromKey12Blob(overalls, migrated_cmk_key12_blob),
                   _.WithStatus<TPMError>(
                       "Failed to parse the encrypted TPM_MIGRATE_ASYMKEY blob "
                       "from the TPM_KEY12 blob"));

  if (encrypted_tpm_migrate_asymkey_blob.size() !=
      kMigrationDestinationKeySizeBytes) {
    return MakeStatus<TPMError>(
        "Failed to parse the encrypted TPM_MIGRATE_ASYMKEY blob due to size "
        "mismatch",
        TPMRetryAction::kNoRetry);
  }

  // Perform the RSA OAEP decryption of the encrypted TPM_MIGRATE_ASYMKEY blob,
  // using the custom OAEP label parameter as prescribed by the TPM 1.2 specs.
  SecureBlob decrypted_tpm_migrate_asymkey_blob;
  if (!RsaOaepDecrypt(
          SecureBlob(encrypted_tpm_migrate_asymkey_blob),
          SecureBlob(std::begin(kTpmRsaOaepLabel), std::end(kTpmRsaOaepLabel)),
          &migration_destination_rsa, &decrypted_tpm_migrate_asymkey_blob)) {
    return MakeStatus<TPMError>(
        "Failed to RSA-decrypt the encrypted TPM_MIGRATE_ASYMKEY blob",
        TPMRetryAction::kNoRetry);
  }

  if (decrypted_tpm_migrate_asymkey_blob.size() !=
      migration_random_blob.size()) {
    return MakeStatus<TPMError>(
        "Failed to decrypt TPM_MIGRATE_ASYMKEY blob due to size mismatch",
        TPMRetryAction::kNoRetry);
  }

  // XOR the decrypted TPM_MIGRATE_ASYMKEY blob with the migration random
  // XOR-mask.
  Blob xored_decrypted_tpm_migrate_asymkey_blob(
      decrypted_tpm_migrate_asymkey_blob.begin(),
      decrypted_tpm_migrate_asymkey_blob.end());
  XorBytes(xored_decrypted_tpm_migrate_asymkey_blob.data(),
           migration_random_blob.data(),
           xored_decrypted_tpm_migrate_asymkey_blob.size());

  // Perform the RSA OAEP decoding (not decryption) of the XOR'ed decrypted
  // TPM_MIGRATE_ASYMKEY blob.
  // The OAEP label parameter is equal to concatenation of
  // |msa_composite_digest| and |cmk_pubkey_digest|.
  // The OAEP seed parameter is extracted as well, because it contains a part of
  // the private key data.
  // Note that our own implementation of OAEP decoding is used instead of the
  // OpenSSL's one, as the latter doesn't return the decoded seed.
  const Blob tpm_migrate_asymkey_oaep_label_blob =
      brillo::CombineBlobs({msa_composite_digest, cmk_pubkey_digest});

  SecureBlob tpm_migrate_asymkey_oaep_seed_blob;
  SecureBlob tpm_migrate_asymkey_blob;
  ASSIGN_OR_RETURN(
      const DecodeOaepMgf1EncodingResult& tpm_migrate_asymkey,
      DecodeOaepMgf1Encoding(overalls, xored_decrypted_tpm_migrate_asymkey_blob,
                             kTpmMigrateAsymkeyBlobSize,
                             tpm_migrate_asymkey_oaep_label_blob),
      _.WithStatus<TPMError>("Failed to perform RSA OAEP decoding of the "
                             "XOR'ed decrypted TPM_MIGRATE_ASYMKEY blob"));

  // Parse the resulting CMK's secret prime from the TPM_MIGRATE_ASYMKEY blob
  // and the seed blob.
  ASSIGN_OR_RETURN(
      const SecureBlob& cmk_secret_prime,
      ParseRsaSecretPrimeFromTpmMigrateAsymkeyBlob(tpm_migrate_asymkey.message,
                                                   tpm_migrate_asymkey.seed),
      _.WithStatus<TPMError>(
          "Failed to parse the private key from the TPM_MIGRATE_ASYMKEY blob"));

  // Build the OpenSSL RSA structure holding the private key.
  ASSIGN_OR_RETURN(
      crypto::ScopedRSA cmk_rsa,
      ParseRsaFromTpmPubkeyBlob(overalls, cmk_pubkey),
      _.WithStatus<TPMError>("Failed to parse RSA public key for CMK"));

  if (!FillRsaPrivateKeyFromSecretPrime(cmk_secret_prime, cmk_rsa.get())) {
    return MakeStatus<TPMError>(
        "Failed to create OpenSSL private key object for the certified "
        "migratable key",
        TPMRetryAction::kNoRetry);
  }

  return cmk_rsa;
}

}  // namespace hwsec
