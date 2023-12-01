// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <cstdint>
#include <string>

#include <brillo/secure_blob.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "oobe_config/encryption/openssl_encryption.h"

class Environment {
 public:
  Environment() {
    logging::SetMinLogLevel(logging::LOG_FATAL);  // <- DISABLE LOGGING.
  }
};

void TestDecryptRandom(const uint8_t* data, size_t size) {
  FuzzedDataProvider provider(data, size);

  oobe_config::EncryptedData enc_test_data;

  if (provider.remaining_bytes() < oobe_config::kOpenSslEncryptionKeySize)
    return;

  enc_test_data.key = brillo::SecureBlob(
      provider.ConsumeBytesAsString(oobe_config::kOpenSslEncryptionKeySize));

  // Don't crash with too little data.
  if (provider.remaining_bytes() < oobe_config::kOpenSslEncryptionTagSize +
                                       oobe_config::kOpenSslEncryptionIvSize) {
    return;
  }

  enc_test_data.data =
      brillo::BlobFromString(provider.ConsumeRemainingBytesAsString());

  oobe_config::Decrypt(enc_test_data);
}

void TestDecryptEncryptedData(const uint8_t* data, size_t size) {
  FuzzedDataProvider provider(data, size);

  if (provider.remaining_bytes() < oobe_config::kOpenSslEncryptionKeySize +
                                       oobe_config::kOpenSslEncryptionIvSize)
    return;

  auto key = brillo::SecureBlob(
      provider.ConsumeBytesAsString(oobe_config::kOpenSslEncryptionKeySize));
  auto iv = brillo::BlobFromString(
      provider.ConsumeBytesAsString(oobe_config::kOpenSslEncryptionIvSize));
  auto input_blob =
      brillo::SecureBlob(provider.ConsumeRemainingBytesAsString());

  auto encrypted = oobe_config::Encrypt(input_blob, key, iv);
  CHECK(encrypted.has_value());

  auto decrypted = oobe_config::Decrypt(encrypted.value());

  CHECK(decrypted == input_blob);
}

void TestDecryptEncryptedDataWrongKey(const uint8_t* data, size_t size) {
  FuzzedDataProvider provider(data, size);

  if (provider.remaining_bytes() < oobe_config::kOpenSslEncryptionKeySize)
    return;

  auto wrong_key = brillo::SecureBlob(
      provider.ConsumeBytesAsString(oobe_config::kOpenSslEncryptionKeySize));

  if (provider.remaining_bytes() < oobe_config::kOpenSslEncryptionKeySize +
                                       oobe_config::kOpenSslEncryptionIvSize)
    return;

  auto key = brillo::SecureBlob(
      provider.ConsumeBytesAsString(oobe_config::kOpenSslEncryptionKeySize));
  auto iv = brillo::BlobFromString(
      provider.ConsumeBytesAsString(oobe_config::kOpenSslEncryptionIvSize));
  auto input_blob =
      brillo::SecureBlob(provider.ConsumeRemainingBytesAsString());

  auto encrypted = oobe_config::Encrypt(input_blob, key, iv);

  if (encrypted->key == wrong_key)
    return;  // Just testing decrypting with the wrong key.

  encrypted->key = std::move(wrong_key);
  auto decrypted = oobe_config::Decrypt(encrypted.value());

  CHECK(!decrypted.has_value());
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  static Environment env;

  TestDecryptRandom(data, size);
  TestDecryptEncryptedData(data, size);
  TestDecryptEncryptedDataWrongKey(data, size);

  return 0;
}
