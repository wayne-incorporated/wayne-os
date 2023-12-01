// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <optional>

#include <base/check.h>
#include <base/check_op.h>
#include <base/logging.h>
#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/fuzzers/blob_mutator.h>
#include <openssl/err.h>

#include "cryptohome/cryptohome_common.h"
#include "cryptohome/flatbuffer_schemas/user_secret_stash_container.h"
#include "cryptohome/flatbuffer_schemas/user_secret_stash_payload.h"
#include "cryptohome/user_secret_stash/user_secret_stash.h"

using brillo::Blob;
using brillo::BlobFromString;
using brillo::SecureBlob;
using cryptohome::ResetSecretMapping;
using cryptohome::UserSecretStash;
using cryptohome::UserSecretStashContainer;
using cryptohome::UserSecretStashPayload;
using hwsec_foundation::AesGcmEncrypt;
using hwsec_foundation::kAesGcm256KeySize;
using hwsec_foundation::MutateBlob;

namespace {

constexpr char kResetSecretLabelOne[] = "label1";
constexpr char kResetSecretLabelTwo[] = "label2";

// Performs the static initialization that's needed only once across all fuzzer
// runs.
class Environment {
 public:
  Environment() { logging::SetMinLogLevel(logging::LOGGING_FATAL); }
};

// Clears the OpenSSL error queue on destruction. Useful for preventing fuzzer
// memory leaks.
struct ScopedOpensslErrorClearer {
  ~ScopedOpensslErrorClearer() { ERR_clear_error(); }
};

// Generates mutated blobs of the USS container and the USS main key.
void PrepareMutatedArguments(FuzzedDataProvider* fuzzed_data_provider,
                             Blob* mutated_uss_container,
                             SecureBlob* mutated_uss_main_key) {
  // Create USS payload.
  UserSecretStashPayload uss_payload_struct;
  uss_payload_struct.fek =
      SecureBlob(fuzzed_data_provider->ConsumeRandomLengthString());
  uss_payload_struct.fnek =
      SecureBlob(fuzzed_data_provider->ConsumeRandomLengthString());
  uss_payload_struct.fek_salt =
      SecureBlob(fuzzed_data_provider->ConsumeRandomLengthString());
  uss_payload_struct.fnek_salt =
      SecureBlob(fuzzed_data_provider->ConsumeRandomLengthString());
  uss_payload_struct.fek_sig =
      SecureBlob(fuzzed_data_provider->ConsumeRandomLengthString());
  uss_payload_struct.fnek_sig =
      SecureBlob(fuzzed_data_provider->ConsumeRandomLengthString());

  // Insert two reset secrets for two fixed labels.
  uss_payload_struct.reset_secrets.push_back(ResetSecretMapping{
      .auth_factor_label = kResetSecretLabelOne,
      .reset_secret =
          SecureBlob(fuzzed_data_provider->ConsumeRandomLengthString())});

  uss_payload_struct.reset_secrets.push_back(ResetSecretMapping{
      .auth_factor_label = kResetSecretLabelTwo,
      .reset_secret =
          SecureBlob(fuzzed_data_provider->ConsumeRandomLengthString())});

  // Serialize the USS payload to flatbuffer and mutate it.
  std::optional<SecureBlob> uss_payload_optional =
      uss_payload_struct.Serialize();
  CHECK(uss_payload_optional.has_value());
  Blob uss_payload(uss_payload_optional.value().begin(),
                   uss_payload_optional.value().end());
  Blob mutated_uss_payload = MutateBlob(
      uss_payload, /*min_length=*/1, /*max_length=*/1000, fuzzed_data_provider);

  // Pick up a "random" AES-GCM USS main key. Note that `AesGcmEncrypt()`
  // requires the key to be of exact size.
  Blob uss_main_key = fuzzed_data_provider->ConsumeBytes<uint8_t>(
      hwsec_foundation::kAesGcm256KeySize);
  uss_main_key.resize(hwsec_foundation::kAesGcm256KeySize);

  // Encrypt the mutated USS payload flatbuffer.
  SecureBlob iv, tag, ciphertext;
  CHECK(hwsec_foundation::AesGcmEncrypt(
      SecureBlob(mutated_uss_payload),
      /*ad=*/std::nullopt, SecureBlob(uss_main_key), &iv, &tag, &ciphertext));

  // Create USS container from mutated fields.
  UserSecretStashContainer uss_container_struct;
  uss_container_struct.encryption_algorithm =
      cryptohome::UserSecretStashEncryptionAlgorithm::AES_GCM_256;
  uss_container_struct.ciphertext =
      MutateBlob(Blob(ciphertext.begin(), ciphertext.end()),
                 /*min_length=*/0, /*max_length=*/1000, fuzzed_data_provider);
  uss_container_struct.iv =
      MutateBlob(Blob(iv.begin(), iv.end()),
                 /*min_length=*/0, /*max_length=*/1000, fuzzed_data_provider);
  uss_container_struct.gcm_tag =
      MutateBlob(Blob(tag.begin(), tag.end()), /*min_length=*/0,
                 /*max_length=*/1000, fuzzed_data_provider);

  // Serialize the USS container to flatbuffer and mutate it.
  std::optional<Blob> uss_container = uss_container_struct.Serialize();
  CHECK(uss_container.has_value());
  *mutated_uss_container =
      MutateBlob(uss_container.value(), /*min_length=*/0,
                 /*max_length=*/1000, fuzzed_data_provider);

  // Mutate the USS main key.
  *mutated_uss_main_key =
      SecureBlob(MutateBlob(uss_main_key, /*min_length=*/0,
                            /*max_length=*/hwsec_foundation::kAesGcm256KeySize,
                            fuzzed_data_provider));
}

void AssertStashesEqual(const UserSecretStash& first,
                        const UserSecretStash& second) {
  CHECK(first.GetFileSystemKeyset().Key().fek ==
        second.GetFileSystemKeyset().Key().fek);
  CHECK(first.GetFileSystemKeyset().Key().fnek ==
        second.GetFileSystemKeyset().Key().fnek);
  CHECK(first.GetFileSystemKeyset().Key().fek_salt ==
        second.GetFileSystemKeyset().Key().fek_salt);
  CHECK(first.GetFileSystemKeyset().Key().fnek_salt ==
        second.GetFileSystemKeyset().Key().fnek_salt);
  CHECK(first.GetFileSystemKeyset().KeyReference().fek_sig ==
        second.GetFileSystemKeyset().KeyReference().fek_sig);
  CHECK(first.GetFileSystemKeyset().KeyReference().fnek_sig ==
        second.GetFileSystemKeyset().KeyReference().fnek_sig);
  CHECK(first.GetFileSystemKeyset().chaps_key() ==
        second.GetFileSystemKeyset().chaps_key());
  CHECK_EQ(first.GetCreatedOnOsVersion(), second.GetCreatedOnOsVersion());

  // Check the reset secrets. Do not assert the reset secrets are present,
  // because the fuzzer could've dropped them while mutating the blobs.
  CHECK(first.GetResetSecretForLabel(kResetSecretLabelOne) ==
        second.GetResetSecretForLabel(kResetSecretLabelOne));
  CHECK(first.GetResetSecretForLabel(kResetSecretLabelTwo) ==
        second.GetResetSecretForLabel(kResetSecretLabelTwo));
}

}  // namespace

// Fuzzes the |UserSecretStash::FromEncryptedContainer()| function.
// It starts of a semantically correct USS with a corresponding USS main key,
// and mutates all parameters before passing them to the tested function.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;
  // Prevent OpenSSL errors from accumulating in the error queue and leaking
  // memory across fuzzer executions.
  ScopedOpensslErrorClearer scoped_openssl_error_clearer;

  FuzzedDataProvider fuzzed_data_provider(data, size);

  Blob mutated_uss_container;
  SecureBlob mutated_uss_main_key;
  PrepareMutatedArguments(&fuzzed_data_provider, &mutated_uss_container,
                          &mutated_uss_main_key);

  // The USS decryption may succeed or fail, but never crash.
  cryptohome::CryptohomeStatusOr<std::unique_ptr<UserSecretStash>>
      stash_status = UserSecretStash::FromEncryptedContainer(
          mutated_uss_container, mutated_uss_main_key);

  if (stash_status.ok()) {
    // If the USS was decrypted successfully, its reencryption must succeed as
    // well.
    cryptohome::CryptohomeStatusOr<Blob> reencrypted =
        stash_status.value()->GetEncryptedContainer(mutated_uss_main_key);
    CHECK(reencrypted.ok());

    // Decryption of the reencrypted USS must succeed as well, and the result
    // must be equal to the original USS.
    cryptohome::CryptohomeStatusOr<std::unique_ptr<UserSecretStash>>
        stash2_status = UserSecretStash::FromEncryptedContainer(
            reencrypted.HintOk().value(), mutated_uss_main_key);
    CHECK(stash2_status.ok());
    AssertStashesEqual(*stash_status.value(), *stash2_status.HintOk().value());
  }

  return 0;
}
