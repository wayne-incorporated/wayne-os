// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <cstring>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <libhwsec/backend/tpm1/static_utils.h>
#include <libhwsec/overalls/overalls.h>
#include <libhwsec/overalls/overalls_api.h>
#include <libhwsec-foundation/crypto/sha.h>
#include <libhwsec-foundation/fuzzers/blob_mutator.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <trousers/trousers.h>
#include <trousers/tss.h>

using brillo::Blob;
using brillo::BlobFromString;
using brillo::CombineBlobs;
using brillo::SecureBlob;
using crypto::ScopedRSA;
using hwsec::overalls::GetOveralls;
using hwsec_foundation::MutateBlob;
using hwsec_foundation::Sha1;

namespace {

// Cryptographic constants:
constexpr int kCmkKeySizeBits = 2048;
constexpr int kCmkKeySizeBytes = kCmkKeySizeBits / 8;
constexpr int kCmkPrivateKeySizeBytes = kCmkKeySizeBytes / 2;
constexpr int kMigratedCmkPrivateKeySeedPartSizeBytes = SHA_DIGEST_LENGTH - 4;
constexpr int kMigratedCmkPrivateKeyRestPartSizeBytes =
    kCmkPrivateKeySizeBytes - kMigratedCmkPrivateKeySeedPartSizeBytes;
constexpr int kIntermediateOaepEncodingBytes =
    198;  // Determined by |kCmkKeySizeBits| and the size of
          // |Environment.migration_destination_rsa|.

// The maximum number of additional bytes that the fuzzer can generate when
// doing a blob mutation in the typical case.
constexpr int kFuzzingExtraSizeDelta = 10;
constexpr char kStaticFilesPath[] = "/usr/libexec/fuzzers/";

struct Environment {
  Environment();

  ScopedRSA cmk_rsa;
  ScopedRSA migration_destination_rsa;
};

struct ScopedOpensslErrorClearer {
  ~ScopedOpensslErrorClearer() { ERR_clear_error(); }
};

ScopedRSA LoadRsaPrivateKeyFromPemFile(const base::FilePath& pem_file_path) {
  std::string pem_data;
  CHECK(base::ReadFileToString(pem_file_path, &pem_data));
  crypto::ScopedBIO pem_data_bio(
      BIO_new_mem_buf(pem_data.data(), pem_data.size()));
  CHECK(pem_data_bio);
  crypto::ScopedRSA rsa(PEM_read_bio_RSAPrivateKey(
      pem_data_bio.get(), /*RSA **x=*/nullptr, /*pem_password_cb *cb=*/nullptr,
      /*void *u=*/nullptr));
  CHECK(rsa);
  return rsa;
}

Environment::Environment()
    : cmk_rsa(LoadRsaPrivateKeyFromPemFile(
          base::FilePath(kStaticFilesPath)
              .AppendASCII("fuzzer_key_rsa_2048_1"))),
      migration_destination_rsa(LoadRsaPrivateKeyFromPemFile(
          base::FilePath(kStaticFilesPath)
              .AppendASCII("fuzzer_key_rsa_2048_2"))) {
  logging::SetMinLogLevel(logging::LOGGING_FATAL);
}

// Returns a mutated RSA-OAEP encrypted blob of the given plaintext.
Blob FuzzedRsaOaepEncrypt(const Blob& plaintext,
                          const Blob& oaep_label,
                          RSA* rsa,
                          FuzzedDataProvider* fuzzed_data_provider) {
  // Explicitly do the padding step first, in order to be able to mutate its
  // result before the actual RSA operation.
  Blob padded_blob(RSA_size(rsa));
  RSA_padding_add_PKCS1_OAEP_mgf1(
      padded_blob.data(), padded_blob.size(), plaintext.data(),
      plaintext.size(), oaep_label.data(), oaep_label.size(), nullptr, nullptr);

  Blob fuzzed_padded_blob =
      MutateBlob(padded_blob, /*min_length=*/RSA_size(rsa),
                 /*max_length=*/RSA_size(rsa), fuzzed_data_provider);

  Blob ciphertext(RSA_size(rsa));
  RSA_public_encrypt(fuzzed_padded_blob.size(), fuzzed_padded_blob.data(),
                     ciphertext.data(), rsa, RSA_NO_PADDING);
  return MutateBlob(ciphertext, /*min_length=*/0,
                    /*max_length=*/RSA_size(rsa) + kFuzzingExtraSizeDelta,
                    fuzzed_data_provider);
}

// Creates a four-byte blob containing the specified integer in the TPM
// endianness.
Blob EncodeTpmUint32(uint32_t value) {
  UINT64 dumping_offset = 0;
  Blob encoded_uint32(4);
  Trspi_LoadBlob_UINT32(&dumping_offset, value,
                        const_cast<BYTE*>(encoded_uint32.data()));
  CHECK_EQ(4, dumping_offset);
  return encoded_uint32;
}

// Creates the blob of the TPM_PUBKEY structure that holds information about the
// given RSA public key.
Blob BuildRsaTpmPubkeyBlob(const RSA& rsa) {
  Blob modulus(RSA_size(&rsa));
  const BIGNUM* n;
  RSA_get0_key(&rsa, &n, nullptr, nullptr);
  if (BN_bn2bin(n, modulus.data()) != modulus.size())
    return Blob();

  // Build the TPM_RSA_KEY_PARMS structure.
  TPM_RSA_KEY_PARMS rsa_key_parms;
  rsa_key_parms.keyLength = RSA_size(&rsa) * 8;
  rsa_key_parms.numPrimes = 2;
  // The default exponent is assumed.
  rsa_key_parms.exponentSize = 0;
  rsa_key_parms.exponent = nullptr;

  // Convert the TPM_RSA_KEY_PARMS structure into blob.
  UINT64 offset = 0;
  Trspi_LoadBlob_RSA_KEY_PARMS(&offset, nullptr, &rsa_key_parms);
  Blob rsa_key_parms_blob(offset);
  offset = 0;
  Trspi_LoadBlob_RSA_KEY_PARMS(&offset, rsa_key_parms_blob.data(),
                               &rsa_key_parms);
  CHECK_EQ(offset, rsa_key_parms_blob.size());

  // Build the TPM_PUBKEY structure.
  TPM_PUBKEY pubkey;
  pubkey.algorithmParms.algorithmID = TPM_ALG_RSA;
  pubkey.algorithmParms.encScheme = 0;
  pubkey.algorithmParms.sigScheme = 0;
  pubkey.algorithmParms.parmSize = rsa_key_parms_blob.size();
  pubkey.algorithmParms.parms = rsa_key_parms_blob.data();
  pubkey.pubKey.keyLength = modulus.size();
  pubkey.pubKey.key = const_cast<BYTE*>(modulus.data());

  // Convert the TPM_PUBKEY structure blob into blob.
  offset = 0;
  Trspi_LoadBlob_PUBKEY(&offset, nullptr, &pubkey);
  Blob pubkey_blob(offset);
  offset = 0;
  Trspi_LoadBlob_PUBKEY(&offset, pubkey_blob.data(), &pubkey);
  CHECK_EQ(offset, pubkey_blob.size());
  return pubkey_blob;
}

// Returns the MGF1 mask of the given size built from the given input value.
Blob GetOaepMgf1Mask(const Blob& mgf_input_value, size_t mask_size) {
  Blob mask(mask_size);
  TSS_RESULT tss_result = Trspi_MGF1(TSS_HASH_SHA1, mgf_input_value.size(),
                                     const_cast<BYTE*>(mgf_input_value.data()),
                                     mask.size(), mask.data());
  CHECK_EQ(tss_result, TSS_SUCCESS);
  return mask;
}

// Performs the mutated RSA OAEP MGF1 encoding of the given |message| using the
// OAEP parameters |oaep_label| and |seed|.
// Note that this custom implementation is used instead of the one from OpenSSL,
// because we need to be able to supply a custom seed.
Blob FuzzedOaepMgf1Encode(const Blob& message,
                          const Blob& oaep_label,
                          const Blob& seed,
                          size_t encoded_message_length,
                          FuzzedDataProvider* fuzzed_data_provider) {
  // The comments in this function below refer to the notation that corresponds
  // to the "RSAES-OAEP Encryption Scheme" Algorithm specification and
  // supporting documentation (2000), the "EME-OAEP-Decode" section.
  // The correspondence between the function parameters and the terms in the
  // specification is:
  // * |message| - "M";
  // * |message.size()| - "mLen";
  // * |oaep_label| - "P";
  // * |seed| - "seed";
  // * |encoded_message_length| - "emLen".
  // Note that as the MGF1 mask is used which is based on SHA-1, the "hLen" term
  // corresponds to |SHA_DIGEST_LENGTH|.

  // Step #1 is omitted as not applicable to our implementation - the length of
  // |oaep_label| can't realistically reach the size constraint of SHA-1.
  // Step #2. Unlike in the original, truncate the message if it's too long, in
  // order to simplify the fuzzer.
  size_t message_length = message.size();
  if (message.size() + 2 * SHA_DIGEST_LENGTH + 1 > encoded_message_length)
    message_length = encoded_message_length - 2 * SHA_DIGEST_LENGTH - 1;
  // Step #3. Generate "PS".
  const Blob zeroes_padding(encoded_message_length - message_length -
                            2 * SHA_DIGEST_LENGTH - 1);
  // Step #4. Generate "pHash".
  const Blob oaep_label_digest = Sha1(oaep_label);
  // Step #5. Generate "DB".
  const Blob padded_message =
      CombineBlobs({oaep_label_digest, zeroes_padding, Blob(1, 1),
                    Blob(message.begin(), message.begin() + message_length)});
  // Step #6 is skipped since the seed is passed as an input.
  // Step #7. Generate "dbMask".
  const Blob padded_message_mask =
      GetOaepMgf1Mask(/*mgf_input_value=*/seed,
                      /*mask_size=*/padded_message.size());
  // Step #8. Generate "maskedDB".
  Blob masked_padded_message = padded_message;
  for (size_t i = 0; i < masked_padded_message.size(); ++i)
    masked_padded_message[i] ^= padded_message_mask[i];
  // Step #9. Generate "seedMask".
  const Blob seed_mask =
      GetOaepMgf1Mask(/*mgf_input_value=*/masked_padded_message,
                      /*mask_size=*/seed.size());
  // Step #10. Generate "maskedSeed".
  Blob masked_seed = seed;
  for (size_t i = 0; i < masked_seed.size(); ++i)
    masked_seed[i] ^= seed_mask[i];
  // Step #11. Generate "EM".
  const Blob encoded_message =
      CombineBlobs({masked_seed, masked_padded_message});
  CHECK_EQ(encoded_message.size(), encoded_message_length);

  return MutateBlob(encoded_message, /*min_length=*/0,
                    /*max_length=*/encoded_message_length,
                    fuzzed_data_provider);
}

// Prepares mutated arguments for the ExtractCmkPrivateKeyFromMigratedBlob()
// function: |key12_blob|, |migration_random_blob|, |cmk_pubkey|,
// |fuzzed_cmk_pubkey_digest|, |fuzzed_msa_composite_digest|. The returned
// values are based off valid values with some mutations applied.
void PrepareMutatedArguments(const RSA& cmk_rsa,
                             RSA* migration_destination_rsa,
                             FuzzedDataProvider* fuzzed_data_provider,
                             Blob* key12_blob,
                             Blob* migration_random_blob,
                             Blob* cmk_pubkey,
                             Blob* fuzzed_cmk_pubkey_digest,
                             Blob* fuzzed_msa_composite_digest) {
  // Build the |fuzzed_cmk_secret_prime| temporary value.
  const BIGNUM* cmk_p;
  RSA_get0_factors(&cmk_rsa, &cmk_p, nullptr);
  Blob cmk_secret_prime(BN_num_bytes(cmk_p));
  CHECK_GE(BN_bn2bin(cmk_p, cmk_secret_prime.data()), 0);
  const Blob fuzzed_cmk_secret_prime = MutateBlob(
      cmk_secret_prime, /*min_length=*/kMigratedCmkPrivateKeySeedPartSizeBytes,
      /*max_length=*/cmk_secret_prime.size() + kFuzzingExtraSizeDelta,
      fuzzed_data_provider);

  // Build the |cmk_pubkey| parameter.
  // Note: not mutating it, since the tested function assumes the validity of
  // the blob.
  *cmk_pubkey = BuildRsaTpmPubkeyBlob(cmk_rsa);

  // Build the |cmk_pubkey_digest| parameter.
  const Blob cmk_pubkey_digest = Sha1(*cmk_pubkey);
  *fuzzed_cmk_pubkey_digest = MutateBlob(
      cmk_pubkey_digest, /*min_length=*/0,
      /*max_length=*/cmk_pubkey_digest.size() + kFuzzingExtraSizeDelta,
      fuzzed_data_provider);

  // Build the |msa_composite_digest| parameter.
  const Blob msa_composite_digest =
      fuzzed_data_provider->ConsumeBytes<uint8_t>(SHA_DIGEST_LENGTH);
  *fuzzed_msa_composite_digest = MutateBlob(
      msa_composite_digest,
      /*min_length=*/0,
      /*max_length=*/msa_composite_digest.size() + kFuzzingExtraSizeDelta,
      fuzzed_data_provider);

  // Build the |tpm_migrate_asymkey_oaep_label_blob| temporary value.
  const Blob tpm_migrate_asymkey_oaep_label_blob =
      CombineBlobs({msa_composite_digest, cmk_pubkey_digest});
  const Blob fuzzed_tpm_migrate_asymkey_oaep_label_blob =
      MutateBlob(tpm_migrate_asymkey_oaep_label_blob,
                 /*min_length=*/0,
                 /*max_length=*/tpm_migrate_asymkey_oaep_label_blob.size() +
                     kFuzzingExtraSizeDelta,
                 fuzzed_data_provider);

  // Build the |tpm_migrate_asymkey_oaep_seed_blob| temporary value.
  const Blob tpm_migrate_asymkey_oaep_seed_blob =
      CombineBlobs({EncodeTpmUint32(kCmkPrivateKeySizeBytes),
                    Blob(fuzzed_cmk_secret_prime.begin(),
                         fuzzed_cmk_secret_prime.begin() +
                             kMigratedCmkPrivateKeySeedPartSizeBytes)});
  const Blob fuzzed_tpm_migrate_asymkey_oaep_seed_blob =
      MutateBlob(tpm_migrate_asymkey_oaep_seed_blob,
                 /*min_length=*/tpm_migrate_asymkey_oaep_seed_blob.size(),
                 /*max_length=*/tpm_migrate_asymkey_oaep_seed_blob.size(),
                 fuzzed_data_provider);

  // Build the |tpm_migrate_asymkey_blob| temporary value.
  Blob auth_data =
      fuzzed_data_provider->ConsumeBytes<uint8_t>(SHA_DIGEST_LENGTH);
  auth_data.resize(SHA_DIGEST_LENGTH);
  Blob pub_data_digest =
      fuzzed_data_provider->ConsumeBytes<uint8_t>(SHA_DIGEST_LENGTH);
  pub_data_digest.resize(SHA_DIGEST_LENGTH);
  const Blob tpm_migrate_asymkey_blob = CombineBlobs({
      /*TPM_MIGRATE_ASYMKEY::payload=*/Blob(1, TPM_PT_CMK_MIGRATE),
      /*TPM_MIGRATE_ASYMKEY::usageAuth::authdata=*/
      auth_data,
      /*TPM_MIGRATE_ASYMKEY::pubDataDigest::digest=*/
      pub_data_digest,
      /*TPM_MIGRATE_ASYMKEY::partPrivKeyLen=*/
      EncodeTpmUint32(kMigratedCmkPrivateKeyRestPartSizeBytes),
      /*TPM_MIGRATE_ASYMKEY::partPrivKey=*/
      Blob(fuzzed_cmk_secret_prime.begin() +
               kMigratedCmkPrivateKeySeedPartSizeBytes,
           fuzzed_cmk_secret_prime.end()),
  });
  const Blob fuzzed_tpm_migrate_asymkey_blob = MutateBlob(
      tpm_migrate_asymkey_blob, /*min_length=*/0,
      /*max_length=*/tpm_migrate_asymkey_blob.size(), fuzzed_data_provider);

  // Build the |fuzzed_encoded_tpm_migrate_asymkey_blob| temporary value.
  const Blob fuzzed_encoded_tpm_migrate_asymkey_blob = FuzzedOaepMgf1Encode(
      /*message=*/fuzzed_tpm_migrate_asymkey_blob,
      /*oaep_label=*/fuzzed_tpm_migrate_asymkey_oaep_label_blob,
      /*seed=*/fuzzed_tpm_migrate_asymkey_oaep_seed_blob,
      /*encoded_message_length=*/kIntermediateOaepEncodingBytes,
      fuzzed_data_provider);

  // Build the |migration_random_blob| temporary value.
  *migration_random_blob = fuzzed_data_provider->ConsumeBytes<uint8_t>(
      fuzzed_encoded_tpm_migrate_asymkey_blob.size());
  migration_random_blob->resize(fuzzed_encoded_tpm_migrate_asymkey_blob.size());

  // Build the |xored_encoded_tpm_migrate_asymkey_blob| temporary value.
  Blob xored_encoded_tpm_migrate_asymkey_blob =
      fuzzed_encoded_tpm_migrate_asymkey_blob;
  for (int i = 0; i < fuzzed_encoded_tpm_migrate_asymkey_blob.size(); ++i)
    xored_encoded_tpm_migrate_asymkey_blob[i] ^= (*migration_random_blob)[i];

  // Build the |encrypted_tpm_migrate_asymkey_blob| temporary value.
  const Blob encrypted_tpm_migrate_asymkey_blob = FuzzedRsaOaepEncrypt(
      /*plaintext=*/xored_encoded_tpm_migrate_asymkey_blob,
      /*oaep_label=*/BlobFromString("TCPA"), migration_destination_rsa,
      fuzzed_data_provider);

  // Build the |key12_blob| parameter.
  // Note: not mutating it, since the tested function assumes the validity of
  // the blob.
  TPM_KEY12 key12;
  memset(&key12, 0, sizeof(TPM_KEY12));
  key12.encSize = encrypted_tpm_migrate_asymkey_blob.size();
  key12.encData =
      const_cast<uint8_t*>(encrypted_tpm_migrate_asymkey_blob.data());
  UINT64 key12_dumping_offset = 0;
  Trspi_LoadBlob_KEY12(&key12_dumping_offset, nullptr, &key12);
  key12_blob->resize(key12_dumping_offset);
  key12_dumping_offset = 0;
  Trspi_LoadBlob_KEY12(&key12_dumping_offset, key12_blob->data(), &key12);
  CHECK_EQ(key12_dumping_offset, key12_blob->size());
}

}  // namespace

// Fuzzer for the ExtractCmkPrivateKeyFromMigratedBlob() function that
// implements parsing/decryption of the migration procedure of a TPM 1.2
// Certified Migratable Key.
//
// The fuzzer contains a complex multi-step data preparation procedure, which
// mirrors the parsing/decryption steps of the tested code, together with mixing
// additional mutations on every step. It's expected that this data preparation
// is stable and won't cause big maintenance burden, since it's, basically, just
// a literal inversed implementation of the steps described in the TPM 1.2
// specification, and that part of the specification is considered stable.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment environment;
  // Prevent OpenSSL errors from accumulating in the error queue and leaking the
  // memory across fuzzer executions.
  ScopedOpensslErrorClearer scoped_openssl_error_clearer;

  FuzzedDataProvider fuzzed_data_provider(data, size);

  Blob key12_blob;
  Blob migration_random_blob;
  Blob cmk_pubkey;
  Blob fuzzed_cmk_pubkey_digest;
  Blob fuzzed_msa_composite_digest;
  PrepareMutatedArguments(
      *environment.cmk_rsa.get(), environment.migration_destination_rsa.get(),
      &fuzzed_data_provider, &key12_blob, &migration_random_blob, &cmk_pubkey,
      &fuzzed_cmk_pubkey_digest, &fuzzed_msa_composite_digest);

  hwsec::StatusOr<ScopedRSA> migrated_blob =
      hwsec::ExtractCmkPrivateKeyFromMigratedBlob(
          *GetOveralls(), key12_blob, migration_random_blob, cmk_pubkey,
          fuzzed_cmk_pubkey_digest, fuzzed_msa_composite_digest,
          *environment.migration_destination_rsa.get());

  return 0;
}
