// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/encrypted_container/fscrypt_container.h"

#include <memory>

#include <base/files/file_path.h>
#include <brillo/secure_blob.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/encrypted_container/encrypted_container.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/keyring/fake_keyring.h"

using ::testing::_;
using ::testing::Return;

namespace cryptohome {

class FscryptContainerTest : public ::testing::Test {
 public:
  FscryptContainerTest()
      : backing_dir_(base::FilePath("/a/b/c")),
        key_reference_({.fek_sig = brillo::SecureBlob("random_keysig")}),
        key_({.fek = brillo::SecureBlob("random key")}),
        container_(std::make_unique<FscryptContainer>(backing_dir_,
                                                      key_reference_,
                                                      /*allow_v2=*/true,
                                                      &platform_,
                                                      &keyring_)) {}
  ~FscryptContainerTest() override = default;

 protected:
  base::FilePath backing_dir_;
  FileSystemKeyReference key_reference_;
  FileSystemKey key_;
  MockPlatform platform_;
  FakeKeyring keyring_;
  std::unique_ptr<EncryptedContainer> container_;
};

// Tests the create path for fscrypt containers.
TEST_F(FscryptContainerTest, SetupCreateCheck) {
  EXPECT_CALL(platform_, SetDirCryptoKey(backing_dir_, _))
      .WillOnce(Return(true));

  EXPECT_TRUE(container_->Setup(key_));
  EXPECT_TRUE(platform_.DirectoryExists(backing_dir_));
  EXPECT_TRUE(keyring_.HasKey(Keyring::KeyType::kFscryptV1Key, key_reference_));
}

// Tests the setup path for an existing fscrypt container.
TEST_F(FscryptContainerTest, SetupNoCreateCheck) {
  EXPECT_TRUE(platform_.CreateDirectory(backing_dir_));

  EXPECT_CALL(platform_, SetDirCryptoKey(backing_dir_, _))
      .WillOnce(Return(true));

  EXPECT_TRUE(container_->Setup(key_));
  EXPECT_TRUE(keyring_.HasKey(Keyring::KeyType::kFscryptV1Key, key_reference_));
}

// Tests failure path when adding the encryption key to the kernel/filesystem
// keyring fails.
TEST_F(FscryptContainerTest, SetupFailedEncryptionKeyAdd) {
  keyring_.SetShouldFail(true);
  EXPECT_FALSE(container_->Setup(key_));
  EXPECT_FALSE(
      keyring_.HasKey(Keyring::KeyType::kFscryptV1Key, key_reference_));
}

// Tests failure path when setting the encryption policy for the backing
// directory fails.
TEST_F(FscryptContainerTest, SetupFailedEncryptionKeySet) {
  EXPECT_CALL(platform_, SetDirCryptoKey(backing_dir_, _))
      .WillOnce(Return(false));

  EXPECT_FALSE(container_->Setup(key_));
  // TODO(dlunev): make sure key is cleaned up in this situation. It is not now.
}

// Tests the teardown invalidates the key.
TEST_F(FscryptContainerTest, TeardownInvalidateKey) {
  EXPECT_CALL(platform_, SetDirCryptoKey(backing_dir_, _))
      .WillOnce(Return(true));
  EXPECT_TRUE(container_->Setup(key_));
  EXPECT_TRUE(keyring_.HasKey(Keyring::KeyType::kFscryptV1Key, key_reference_));
  EXPECT_TRUE(container_->Teardown());
  EXPECT_FALSE(
      keyring_.HasKey(Keyring::KeyType::kFscryptV1Key, key_reference_));
}

}  // namespace cryptohome
