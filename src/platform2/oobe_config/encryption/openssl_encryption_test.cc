// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "oobe_config/encryption/openssl_encryption.h"

#include <optional>

#include <brillo/secure_blob.h>
#include <gtest/gtest.h>

namespace oobe_config {

namespace {

const brillo::SecureBlob kKey(kOpenSslEncryptionKeySize, 60);
const brillo::SecureBlob kSensitiveData(859, 61);
const brillo::Blob kData(857, 63);

}  // namespace

TEST(RollbackOpenSslEncryptionTest, EncryptDecrypt) {
  std::optional<EncryptedData> encrypted_data = Encrypt(kSensitiveData);
  ASSERT_TRUE(encrypted_data.has_value());

  // Make sure data was changed by encryption.
  auto first_mismatch =
      std::mismatch(std::begin(kSensitiveData), std::end(kSensitiveData),
                    std::begin(encrypted_data->data));
  ASSERT_FALSE(first_mismatch.first == std::end(kSensitiveData));

  std::optional<brillo::SecureBlob> decrypted_data = Decrypt(*encrypted_data);
  ASSERT_TRUE(decrypted_data.has_value());
  ASSERT_EQ(kSensitiveData, *decrypted_data);
}

TEST(RollbackOpenSslEncryptionTest, EncryptDecryptWithWrongKey) {
  std::optional<EncryptedData> encrypted_data = Encrypt(kSensitiveData);
  ASSERT_TRUE(encrypted_data.has_value());

  std::optional<brillo::SecureBlob> decrypted_data =
      Decrypt({encrypted_data->data, kKey});
  ASSERT_FALSE(decrypted_data.has_value());
}

TEST(RollbackOpenSslEncryptionTest, DecryptModifyData) {
  std::optional<EncryptedData> encrypted_data = Encrypt(kSensitiveData);
  ASSERT_TRUE(encrypted_data.has_value());
  encrypted_data->data[1]++;
  std::optional<brillo::SecureBlob> decrypted_data =
      Decrypt(encrypted_data.value());
  ASSERT_FALSE(decrypted_data.has_value());
}

TEST(RollbackOpenSslEncryptionTest, DecryptModifyKey) {
  std::optional<EncryptedData> encrypted_data = Encrypt(kSensitiveData);
  ASSERT_TRUE(encrypted_data.has_value());
  encrypted_data->key[1]++;
  std::optional<brillo::SecureBlob> decrypted_data =
      Decrypt(encrypted_data.value());
  ASSERT_FALSE(decrypted_data.has_value());
}

TEST(RollbackOpenSslEncryptionTest, DecryptNonesense) {
  std::optional<brillo::SecureBlob> decrypted_data = Decrypt({kData, kKey});
  ASSERT_FALSE(decrypted_data.has_value());
}

TEST(RollbackOpenSslEncryptionTest, EncryptedDataSize) {
  std::optional<EncryptedData> encrypted_data = Encrypt(kSensitiveData);
  ASSERT_TRUE(encrypted_data.has_value());

  EXPECT_GE(encrypted_data->data.size(), kSensitiveData.size() +
                                             kOpenSslEncryptionTagSize +
                                             kOpenSslEncryptionIvSize);
  EXPECT_EQ(encrypted_data->key.size(), kOpenSslEncryptionKeySize);
}

}  // namespace oobe_config
