// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <libhwsec-foundation/crypto/rsa.h>
#include <libhwsec-foundation/fuzzers/blob_mutator.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

using brillo::Blob;
using brillo::BlobFromString;
using brillo::SecureBlob;
using crypto::ScopedRSA;
using hwsec_foundation::MutateBlob;
using hwsec_foundation::RsaOaepDecrypt;

namespace {

constexpr char kStaticFilesPath[] = "/usr/libexec/fuzzers/";

constexpr int kMaxPlaintextLength = 5;
constexpr int kMaxOaepLabelLength = 5;

struct Environment {
  Environment();

  // The RSA keys loaded from the data files installed next to the fuzzer.
  static constexpr int kRsaKeyCount = 8;
  ScopedRSA rsa_keys[kRsaKeyCount];
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

Environment::Environment() {
  logging::SetMinLogLevel(logging::LOGGING_FATAL);

  int key_index = 0;
  for (int key_size : {512, 1024, 2048, 4096}) {
    for (int current_key_number : {1, 2}) {
      const base::FilePath key_file_path =
          base::FilePath(kStaticFilesPath)
              .AppendASCII(base::StringPrintf("fuzzer_key_rsa_%d_%d",
                                              key_size, current_key_number));
      CHECK_LT(key_index, kRsaKeyCount);
      rsa_keys[key_index] = LoadRsaPrivateKeyFromPemFile(key_file_path);
      ++key_index;
    }
  }
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
  return MutateBlob(ciphertext, /*min_length=*/0, /*max_length=*/RSA_size(rsa),
                    fuzzed_data_provider);
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment environment;
  // Prevent OpenSSL errors from accumulating in the error queue and leaking the
  // memory across fuzzer executions.
  ScopedOpensslErrorClearer scoped_openssl_error_clearer;

  FuzzedDataProvider fuzzed_data_provider(data, size);

  RSA* const encryption_rsa =
      environment
          .rsa_keys[fuzzed_data_provider.ConsumeIntegralInRange(
              0, Environment::kRsaKeyCount - 1)]
          .get();
  RSA* const decryption_rsa =
      environment
          .rsa_keys[fuzzed_data_provider.ConsumeIntegralInRange(
              0, Environment::kRsaKeyCount - 1)]
          .get();

  // Prepare fuzzed parameters for the tested function, based off real
  // RSA-encoded blobs.
  const Blob plaintext = BlobFromString(
      fuzzed_data_provider.ConsumeRandomLengthString(kMaxPlaintextLength));
  const Blob oaep_label = BlobFromString(
      fuzzed_data_provider.ConsumeRandomLengthString(kMaxOaepLabelLength));
  const Blob fuzzed_ciphertext = FuzzedRsaOaepEncrypt(
      plaintext, oaep_label, encryption_rsa, &fuzzed_data_provider);

  const Blob fuzzed_oaep_label =
      MutateBlob(oaep_label, /*min_length=*/0,
                 /*max_length=*/kMaxOaepLabelLength, &fuzzed_data_provider);

  // Run the fuzzed function.
  SecureBlob decrypted_data;
  if (hwsec_foundation::RsaOaepDecrypt(SecureBlob(fuzzed_ciphertext),
                                       SecureBlob(fuzzed_oaep_label),
                                       decryption_rsa, &decrypted_data)) {
    // Assert that the decryption result must be equal to the plaintext that was
    // encrypted above - it's unrealistic for the fuzzer to find a blob that is
    // a valid ciphertext of some different blob.
    CHECK(SecureBlob(plaintext) == decrypted_data);
  }
  return 0;
}
