// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/crypto/scrypt.h"

#include <openssl/rsa.h>

#include <base/base64.h>
#include <base/check.h>
#include <brillo/secure_blob.h>
#include <crypto/scoped_openssl_types.h>
#include <gtest/gtest.h>

#include "libhwsec-foundation/crypto/secure_blob_util.h"

using brillo::SecureBlob;

namespace hwsec_foundation {

TEST(ScryptTest, DeriveSecretsScrypt) {
  brillo::SecureBlob passkey("passkey");
  brillo::SecureBlob salt("salt");

  const size_t secret_size = 16;
  brillo::SecureBlob result1(secret_size), result2(secret_size),
      result3(secret_size);

  EXPECT_TRUE(
      DeriveSecretsScrypt(passkey, salt, {&result1, &result2, &result3}));

  EXPECT_NE(brillo::SecureBlob(), result1);
  EXPECT_NE(brillo::SecureBlob(), result2);
  EXPECT_NE(brillo::SecureBlob(), result3);
}

TEST(ScryptTest, DeriveSecretsScryptEmptySecrets) {
  brillo::SecureBlob passkey("passkey");
  brillo::SecureBlob salt("salt");

  std::vector<brillo::SecureBlob*> gen_secrets;
  EXPECT_FALSE(DeriveSecretsScrypt(passkey, salt, gen_secrets));

  brillo::SecureBlob empty_blob;
  EXPECT_FALSE(DeriveSecretsScrypt(passkey, salt, {&empty_blob}));
}

}  // namespace hwsec_foundation
