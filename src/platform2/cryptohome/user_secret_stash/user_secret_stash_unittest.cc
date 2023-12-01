// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/user_secret_stash/user_secret_stash.h"

#include <base/test/scoped_chromeos_version_info.h>
#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/aes.h>
#include <libhwsec-foundation/utility/crypto.h>

#include <algorithm>
#include <limits>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

#include "cryptohome/cryptohome_common.h"
#include "cryptohome/flatbuffer_schemas/user_secret_stash_container.h"
#include "cryptohome/flatbuffer_schemas/user_secret_stash_payload.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/encrypted_container/filesystem_key.h"
#include "cryptohome/storage/file_system_keyset.h"
#include "cryptohome/storage/file_system_keyset_test_utils.h"

using ::cryptohome::error::CryptohomeError;
using ::hwsec_foundation::AesGcmDecrypt;
using ::hwsec_foundation::AesGcmEncrypt;
using ::hwsec_foundation::kAesGcm256KeySize;
using ::hwsec_foundation::status::OkStatus;
using ::hwsec_foundation::utility::CreateSecureRandomBlob;

namespace cryptohome {

namespace {

bool FindBlobInBlob(const brillo::Blob& haystack,
                    const brillo::SecureBlob& needle) {
  return std::search(haystack.begin(), haystack.end(), needle.begin(),
                     needle.end()) != haystack.end();
}

class UserSecretStashTest : public ::testing::Test {
 protected:
  // Fake file system keyset data:
  const brillo::SecureBlob kFek = brillo::SecureBlob("fek");
  const brillo::SecureBlob kFnek = brillo::SecureBlob("fnek");
  const brillo::SecureBlob kFekSalt = brillo::SecureBlob("fek-salt");
  const brillo::SecureBlob kFnekSalt = brillo::SecureBlob("fnek-salt");
  const brillo::SecureBlob kFekSig = brillo::SecureBlob("fek-sig");
  const brillo::SecureBlob kFnekSig = brillo::SecureBlob("fnek-sig");
  const brillo::SecureBlob kChapsKey = brillo::SecureBlob("chaps-key");
  const FileSystemKeyset kFileSystemKeyset = FileSystemKeyset(
      FileSystemKey{
          .fek = kFek,
          .fnek = kFnek,
          .fek_salt = kFekSalt,
          .fnek_salt = kFnekSalt,
      },
      FileSystemKeyReference{
          .fek_sig = kFekSig,
          .fnek_sig = kFnekSig,
      },
      kChapsKey);

  // Fake USS Main Key.
  const brillo::SecureBlob kMainKey =
      brillo::SecureBlob(kAesGcm256KeySize, 0xA);

  void SetUp() override {
    CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> uss_status =
        UserSecretStash::CreateRandom(kFileSystemKeyset);
    ASSERT_TRUE(uss_status.ok());
    stash_ = std::move(uss_status).value();
  }

  std::unique_ptr<UserSecretStash> stash_;
};

}  // namespace

TEST_F(UserSecretStashTest, CreateRandom) {
  // The secrets should be created randomly and never collide (in practice).
  EXPECT_THAT(stash_->GetFileSystemKeyset(),
              FileSystemKeysetEquals(kFileSystemKeyset));
}

// Basic test of the `CreateRandomMainKey()` method.
TEST_F(UserSecretStashTest, CreateRandomMainKey) {
  brillo::SecureBlob main_key = UserSecretStash::CreateRandomMainKey();
  EXPECT_FALSE(main_key.empty());
}

// Test the secret main keys created by `CreateRandomMainKey()` don't repeat (in
// practice).
TEST_F(UserSecretStashTest, CreateRandomMainKeyNotConstant) {
  brillo::SecureBlob main_key_1 = UserSecretStash::CreateRandomMainKey();
  brillo::SecureBlob main_key_2 = UserSecretStash::CreateRandomMainKey();
  EXPECT_NE(main_key_1, main_key_2);
}

// Verify the getters/setters of the wrapped key fields.
TEST_F(UserSecretStashTest, MainKeyWrapping) {
  const char kWrappingId1[] = "id1";
  const char kWrappingId2[] = "id2";
  const brillo::SecureBlob kWrappingKey1(kAesGcm256KeySize, 0xB);
  const brillo::SecureBlob kWrappingKey2(kAesGcm256KeySize, 0xC);

  // Initially there's no wrapped key.
  EXPECT_FALSE(stash_->HasWrappedMainKey(kWrappingId1));
  EXPECT_FALSE(stash_->HasWrappedMainKey(kWrappingId2));

  // And the main key wrapped with two wrapping keys.
  EXPECT_TRUE(stash_
                  ->AddWrappedMainKey(kMainKey, kWrappingId1, kWrappingKey1,
                                      OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  EXPECT_TRUE(stash_->HasWrappedMainKey(kWrappingId1));
  EXPECT_TRUE(stash_
                  ->AddWrappedMainKey(kMainKey, kWrappingId2, kWrappingKey2,
                                      OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  EXPECT_TRUE(stash_->HasWrappedMainKey(kWrappingId2));
  // Duplicate wrapping IDs aren't allowed if override is not enabled.
  EXPECT_FALSE(stash_
                   ->AddWrappedMainKey(kMainKey, kWrappingId1, kWrappingKey1,
                                       OverwriteExistingKeyBlock::kDisabled)
                   .ok());
  // Same wrapping ID overrides the duplicate if override is enabled.
  EXPECT_TRUE(stash_
                  ->AddWrappedMainKey(kMainKey, kWrappingId1, kWrappingKey1,
                                      OverwriteExistingKeyBlock::kEnabled)
                  .ok());
  // The main key can be unwrapped using any of the wrapping keys.
  CryptohomeStatusOr<brillo::SecureBlob> got_main_key1 =
      stash_->UnwrapMainKey(kWrappingId1, kWrappingKey1);
  ASSERT_TRUE(got_main_key1.ok());
  EXPECT_EQ(got_main_key1.value(), kMainKey);
  CryptohomeStatusOr<brillo::SecureBlob> got_main_key2 =
      stash_->UnwrapMainKey(kWrappingId2, kWrappingKey2);
  ASSERT_TRUE(got_main_key2.ok());
  EXPECT_EQ(got_main_key2.value(), kMainKey);

  // Removal of one wrapped key block preserves the other.
  EXPECT_TRUE(stash_->RemoveWrappedMainKey(kWrappingId1));
  EXPECT_FALSE(stash_->HasWrappedMainKey(kWrappingId1));
  EXPECT_TRUE(stash_->HasWrappedMainKey(kWrappingId2));
  // Removing a non-existing wrapped key block fails.
  EXPECT_FALSE(stash_->RemoveWrappedMainKey(kWrappingId1));
}

TEST_F(UserSecretStashTest, GetEncryptedUSS) {
  // Add two reset secrets to make sure encryption covers those.
  brillo::SecureBlob reset_secret1 =
      CreateSecureRandomBlob(CRYPTOHOME_RESET_SECRET_LENGTH);
  brillo::SecureBlob reset_secret2 =
      CreateSecureRandomBlob(CRYPTOHOME_RESET_SECRET_LENGTH);
  brillo::SecureBlob reset_secret3 =
      CreateSecureRandomBlob(CRYPTOHOME_RESET_SECRET_LENGTH);
  ASSERT_TRUE(stash_->SetResetSecretForLabel("label1", reset_secret1));
  ASSERT_TRUE(stash_->SetResetSecretForLabel("label2", reset_secret2));
  ASSERT_TRUE(stash_->SetRateLimiterResetSecret(AuthFactorType::kFingerprint,
                                                reset_secret3));

  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());

  // No raw secrets in the encrypted USS, which is written to disk.
  EXPECT_FALSE(
      FindBlobInBlob(*uss_container, stash_->GetFileSystemKeyset().Key().fek));
  EXPECT_FALSE(FindBlobInBlob(*uss_container, reset_secret1));
  EXPECT_FALSE(FindBlobInBlob(*uss_container, reset_secret2));
  EXPECT_FALSE(FindBlobInBlob(*uss_container, reset_secret3));
}

TEST_F(UserSecretStashTest, EncryptAndDecryptUSS) {
  ASSERT_TRUE(stash_->SetResetSecretForLabel("label1", {0xAA, 0xBB}));
  ASSERT_TRUE(stash_->SetRateLimiterResetSecret(AuthFactorType::kFingerprint,
                                                {0xCC, 0xDD}));

  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());

  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash2 =
      UserSecretStash::FromEncryptedContainer(uss_container.value(), kMainKey);
  ASSERT_TRUE(stash2.ok());

  EXPECT_THAT(stash_->GetFileSystemKeyset(),
              FileSystemKeysetEquals(stash2.value()->GetFileSystemKeyset()));
  EXPECT_EQ(stash_->GetResetSecretForLabel("label1").value(),
            stash2.value()->GetResetSecretForLabel("label1").value());
  EXPECT_EQ(
      stash_->GetRateLimiterResetSecret(AuthFactorType::kFingerprint).value(),
      stash2.value()
          ->GetRateLimiterResetSecret(AuthFactorType::kFingerprint)
          .value());
}

// Test that deserialization fails on an empty blob. Normally this never occurs,
// but we verify to be resilient against accidental or intentional file
// corruption.
TEST_F(UserSecretStashTest, DecryptErrorEmptyBuf) {
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   /*flatbuffer=*/brillo::Blob(), kMainKey)
                   .ok());
}

// Test that deserialization fails on a corrupted flatbuffer. Normally this
// never occurs, but we verify to be resilient against accidental or intentional
// file corruption.
TEST_F(UserSecretStashTest, DecryptErrorCorruptedBuf) {
  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());

  brillo::Blob corrupted_uss_container = uss_container.value();
  for (uint8_t& byte : corrupted_uss_container)
    byte ^= 1;

  EXPECT_FALSE(
      UserSecretStash::FromEncryptedContainer(corrupted_uss_container, kMainKey)
          .ok());
}

// Test that decryption fails on an empty decryption key.
TEST_F(UserSecretStashTest, DecryptErrorEmptyKey) {
  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(uss_container.value(),
                                                       /*main_key=*/{})
                   .ok());
}

// Test that decryption fails on a decryption key of a wrong size.
TEST_F(UserSecretStashTest, DecryptErrorKeyBadSize) {
  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());

  brillo::SecureBlob bad_size_main_key = kMainKey;
  bad_size_main_key.resize(kAesGcm256KeySize - 1);

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(uss_container.value(),
                                                       bad_size_main_key)
                   .ok());
}

// Test that decryption fails on a wrong decryption key.
TEST_F(UserSecretStashTest, DecryptErrorWrongKey) {
  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());

  brillo::SecureBlob wrong_main_key = kMainKey;
  wrong_main_key[0] ^= 1;

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(uss_container.value(),
                                                       wrong_main_key)
                   .ok());
}

// Test that wrapped key blocks are [de]serialized correctly.
TEST_F(UserSecretStashTest, EncryptAndDecryptUSSWithOverridenWrappedKey) {
  const char kWrappingId1[] = "id1";
  const brillo::SecureBlob kWrappingKey1(kAesGcm256KeySize, 0xB);
  const brillo::SecureBlob kWrappingKey2(kAesGcm256KeySize, 0xC);

  // Add wrapped key block. First write a key block and then override it with
  // a different key block to test that clobbering works.
  EXPECT_TRUE(stash_
                  ->AddWrappedMainKey(kMainKey, kWrappingId1, kWrappingKey1,
                                      OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  // Overwrite with the second key.
  EXPECT_TRUE(stash_
                  ->AddWrappedMainKey(kMainKey, kWrappingId1, kWrappingKey2,
                                      OverwriteExistingKeyBlock::kEnabled)
                  .ok());

  // Do the serialization-deserialization roundtrip with the USS.
  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash2 =
      UserSecretStash::FromEncryptedContainer(uss_container.value(), kMainKey);
  ASSERT_TRUE(stash2.ok());

  // The wrapped key block with second key is present in the loaded stash and
  // can be decrypted.

  EXPECT_TRUE(stash2.value()->HasWrappedMainKey(kWrappingId1));

  CryptohomeStatusOr<brillo::SecureBlob> got_main_key1 =
      stash2.value()->UnwrapMainKey(kWrappingId1, kWrappingKey1);
  ASSERT_FALSE(got_main_key1.ok());

  got_main_key1 = stash2.value()->UnwrapMainKey(kWrappingId1, kWrappingKey2);
  ASSERT_TRUE(got_main_key1.ok());

  EXPECT_EQ(got_main_key1.value(), kMainKey);
}

// Test that wrapped key blocks are [de]serialized correctly.
TEST_F(UserSecretStashTest, EncryptAndDecryptUSSWithWrappedKeys) {
  const char kWrappingId1[] = "id1";
  const char kWrappingId2[] = "id2";
  const brillo::SecureBlob kWrappingKey1(kAesGcm256KeySize, 0xB);
  const brillo::SecureBlob kWrappingKey2(kAesGcm256KeySize, 0xC);

  // Add wrapped key blocks.
  EXPECT_TRUE(stash_
                  ->AddWrappedMainKey(kMainKey, kWrappingId1, kWrappingKey1,
                                      OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  EXPECT_TRUE(stash_
                  ->AddWrappedMainKey(kMainKey, kWrappingId2, kWrappingKey2,
                                      OverwriteExistingKeyBlock::kDisabled)
                  .ok());
  // Do the serialization-deserialization roundtrip with the USS.
  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash2 =
      UserSecretStash::FromEncryptedContainer(uss_container.value(), kMainKey);
  ASSERT_TRUE(stash2.ok());

  // The wrapped key blocks are present in the loaded stash and can be
  // decrypted.
  EXPECT_TRUE(stash2.value()->HasWrappedMainKey(kWrappingId1));
  EXPECT_TRUE(stash2.value()->HasWrappedMainKey(kWrappingId2));
  CryptohomeStatusOr<brillo::SecureBlob> got_main_key1 =
      stash2.value()->UnwrapMainKey(kWrappingId1, kWrappingKey1);
  ASSERT_TRUE(got_main_key1.ok());
  EXPECT_EQ(got_main_key1.value(), kMainKey);
}

// Test that the USS can be loaded and decrypted using the wrapping key stored
// in it.
TEST_F(UserSecretStashTest, EncryptAndDecryptUSSViaWrappedKey) {
  // Add a wrapped key block.
  const char kWrappingId[] = "id";
  const brillo::SecureBlob kWrappingKey(kAesGcm256KeySize, 0xB);
  EXPECT_TRUE(stash_
                  ->AddWrappedMainKey(kMainKey, kWrappingId, kWrappingKey,
                                      OverwriteExistingKeyBlock::kDisabled)
                  .ok());

  // Encrypt the USS.
  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());

  // The USS can be decrypted using the wrapping key.
  brillo::SecureBlob unwrapped_main_key;
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash2 =
      UserSecretStash::FromEncryptedContainerWithWrappingKey(
          uss_container.value(), kWrappingId, kWrappingKey,
          &unwrapped_main_key);
  ASSERT_TRUE(stash2.ok());
  EXPECT_THAT(stash_->GetFileSystemKeyset(),
              FileSystemKeysetEquals(stash2.value()->GetFileSystemKeyset()));
  EXPECT_EQ(unwrapped_main_key, kMainKey);
}

TEST_F(UserSecretStashTest, EncryptAndDecryptUSSWithUserMetadata) {
  uint64_t fake_fp_rlimiter_id = 123;
  ASSERT_TRUE(stash_->InitializeFingerprintRateLimiterId(fake_fp_rlimiter_id));

  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());

  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash2 =
      UserSecretStash::FromEncryptedContainer(uss_container.value(), kMainKey);
  ASSERT_TRUE(stash2.ok());

  EXPECT_THAT(stash_->GetFileSystemKeyset(),
              FileSystemKeysetEquals(stash2.value()->GetFileSystemKeyset()));
  EXPECT_EQ(stash2.value()->GetFingerprintRateLimiterId(), fake_fp_rlimiter_id);
}

TEST_F(UserSecretStashTest, ReadUserMetadataFromEncryptedUSS) {
  uint64_t fake_fp_rlimiter_id = 123;
  ASSERT_TRUE(stash_->InitializeFingerprintRateLimiterId(fake_fp_rlimiter_id));

  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());
  CryptohomeStatusOr<UserMetadata> user_metadata =
      UserSecretStash::GetUserMetadata(uss_container.value());
  ASSERT_TRUE(user_metadata.ok());

  EXPECT_EQ(user_metadata.value().fingerprint_rate_limiter_id,
            fake_fp_rlimiter_id);
}

TEST_F(UserSecretStashTest, EncryptAndDecryptUSSWithNoFingerprintRateLimiter) {
  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());

  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash2 =
      UserSecretStash::FromEncryptedContainer(uss_container.value(), kMainKey);
  ASSERT_TRUE(stash2.ok());

  EXPECT_THAT(stash_->GetFileSystemKeyset(),
              FileSystemKeysetEquals(stash2.value()->GetFileSystemKeyset()));
  EXPECT_EQ(stash2.value()->GetFingerprintRateLimiterId(), std::nullopt);
}

// Test the USS experiment state is off by default, but can be toggled in tests.
TEST_F(UserSecretStashTest, ExperimentState) {
  // The experiment is on by default.
  MockPlatform platform;
  EXPECT_TRUE(IsUserSecretStashExperimentEnabled(&platform));

  // Verify the test can toggle the experiment state.
  SetUserSecretStashExperimentForTesting(/*enabled=*/false);
  EXPECT_FALSE(IsUserSecretStashExperimentEnabled(&platform));

  // Unset the experiment override to avoid affecting other test cases.
  ResetUserSecretStashExperimentForTesting();
}

// Test that a newly created USS has the current OS version stored.
TEST_F(UserSecretStashTest, OsVersion) {
  constexpr char kLsbRelease[] =
      "CHROMEOS_RELEASE_NAME=Chrome "
      "OS\nCHROMEOS_RELEASE_VERSION=11012.0.2018_08_28_1422\n";
  base::test::ScopedChromeOSVersionInfo scoped_version(
      kLsbRelease, /*lsb_release_time=*/base::Time());

  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash1 =
      UserSecretStash::CreateRandom(kFileSystemKeyset);
  ASSERT_TRUE(stash1.ok());
  EXPECT_EQ(stash1.value()->GetCreatedOnOsVersion(), "11012.0.2018_08_28_1422");
}

// Test that the OS version is stored in the USS and doesn't change even when
// the OS updates.
TEST_F(UserSecretStashTest, OsVersionStays) {
  constexpr char kLsbRelease1[] =
      "CHROMEOS_RELEASE_NAME=Chrome "
      "OS\nCHROMEOS_RELEASE_VERSION=11012.0.2018_08_28_1422\n";
  constexpr char kLsbRelease2[] =
      "CHROMEOS_RELEASE_NAME=Chrome "
      "OS\nCHROMEOS_RELEASE_VERSION=22222.0.2028_01_01_9999\n";

  // Create and encrypt the USS on the version 1.
  brillo::Blob uss_container;
  {
    base::test::ScopedChromeOSVersionInfo scoped_version1(
        kLsbRelease1, /*lsb_release_time=*/base::Time());
    CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash1 =
        UserSecretStash::CreateRandom(kFileSystemKeyset);
    ASSERT_TRUE(stash1.ok());
    CryptohomeStatusOr<brillo::Blob> uss_container_status =
        stash1.value()->GetEncryptedContainer(kMainKey);
    ASSERT_TRUE(uss_container_status.ok());
    uss_container = std::move(uss_container_status).value();
  }

  // Decrypt the USS on the version 2. Check that the field still mentions
  // version 1.
  {
    base::test::ScopedChromeOSVersionInfo scoped_version2(
        kLsbRelease2, /*lsb_release_time=*/base::Time());
    CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash2 =
        UserSecretStash::FromEncryptedContainer(uss_container, kMainKey);
    ASSERT_TRUE(stash2.ok());
    EXPECT_EQ(stash2.value()->GetCreatedOnOsVersion(),
              "11012.0.2018_08_28_1422");
  }
}

// Test that the USS is correctly created and loaded even when reading the OS
// version fails.
TEST_F(UserSecretStashTest, MissingOsVersion) {
  // Note: Normally unit tests don't have access to a CrOS /etc/lsb-release
  // anyway, but this override guarantees that the test passes regardless of
  // that.
  base::test::ScopedChromeOSVersionInfo scoped_version(
      /*lsb_release=*/"", /*lsb_release_time=*/base::Time());

  // A newly created USS should have an empty OS version.
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash =
      UserSecretStash::CreateRandom(kFileSystemKeyset);
  ASSERT_TRUE(stash.ok());
  EXPECT_TRUE(stash.value()->GetCreatedOnOsVersion().empty());

  // Do a encrypt-decrypt roundtrip and verify the OS version is still empty.
  CryptohomeStatusOr<brillo::Blob> uss_container =
      stash_->GetEncryptedContainer(kMainKey);
  ASSERT_TRUE(uss_container.ok());
  CryptohomeStatusOr<std::unique_ptr<UserSecretStash>> stash2 =
      UserSecretStash::FromEncryptedContainer(uss_container.value(), kMainKey);
  ASSERT_TRUE(stash2.ok());
  EXPECT_TRUE(stash2.value()->GetCreatedOnOsVersion().empty());
}

// Test that SetResetSecretForLabel does not overwrite if a reset secret already
// exists.
TEST_F(UserSecretStashTest, DoubleInsertResetSecret) {
  brillo::SecureBlob reset_secret1 = {0xAA, 0xBB, 0xCC};
  brillo::SecureBlob reset_secret2 = {0xDD, 0xEE, 0x11};
  brillo::SecureBlob reset_secret3 = {0x22, 0x33, 0x44};

  EXPECT_TRUE(stash_->SetResetSecretForLabel("label1", reset_secret1));
  EXPECT_TRUE(stash_->SetResetSecretForLabel("label2", reset_secret2));
  EXPECT_FALSE(stash_->SetResetSecretForLabel("label1", reset_secret3));

  EXPECT_EQ(reset_secret1, stash_->GetResetSecretForLabel("label1").value());
}

// Test that SetRateLimiterResetSecret does not overwrite if a reset secret
// already exists.
TEST_F(UserSecretStashTest, DoubleInsertRateLimiterResetSecret) {
  brillo::SecureBlob reset_secret1 = {0xAA, 0xBB, 0xCC};
  brillo::SecureBlob reset_secret2 = {0xDD, 0xEE, 0x11};
  brillo::SecureBlob reset_secret3 = {0x22, 0x33, 0x44};

  EXPECT_TRUE(stash_->SetRateLimiterResetSecret(AuthFactorType::kFingerprint,
                                                reset_secret1));
  EXPECT_TRUE(
      stash_->SetRateLimiterResetSecret(AuthFactorType::kPin, reset_secret2));
  EXPECT_FALSE(stash_->SetRateLimiterResetSecret(AuthFactorType::kFingerprint,
                                                 reset_secret3));

  EXPECT_EQ(
      reset_secret1,
      stash_->GetRateLimiterResetSecret(AuthFactorType::kFingerprint).value());
}

// Test that RemoveResetSecretForLabel successfully removes the reset secret,
// and afterwards it can be inserted again.
TEST_F(UserSecretStashTest, RemoveResetSecretForLabel) {
  brillo::SecureBlob reset_secret1 = {0xAA, 0xBB, 0xCC};
  brillo::SecureBlob reset_secret2 = {0xDD, 0xEE, 0x11};

  EXPECT_TRUE(stash_->SetResetSecretForLabel("label1", reset_secret1));
  EXPECT_TRUE(stash_->SetResetSecretForLabel("label2", reset_secret2));

  EXPECT_TRUE(stash_->RemoveResetSecretForLabel("label1"));
  // No reset secret for label1.
  ASSERT_FALSE(stash_->GetResetSecretForLabel("label1").has_value());
  EXPECT_EQ(reset_secret2, stash_->GetResetSecretForLabel("label2").value());
  // Reset secret for label1 can be inserted again.
  EXPECT_TRUE(stash_->SetResetSecretForLabel("label1", reset_secret1));
}

TEST_F(UserSecretStashTest, GetInitializeFingerprintRateLimiterId) {
  uint64_t fake_id = 123;
  // stash_ is freshly prepared, so it does not have
  // the fingerprint rate limter id.
  ASSERT_EQ(stash_->GetFingerprintRateLimiterId(), std::nullopt);

  // Set the id for the first time should succeed.
  ASSERT_TRUE(stash_->InitializeFingerprintRateLimiterId(fake_id));
  ASSERT_EQ(stash_->GetFingerprintRateLimiterId(), fake_id);

  // Set the id for the 2nd time should fail.
  ASSERT_FALSE(stash_->InitializeFingerprintRateLimiterId(0));
  ASSERT_EQ(stash_->GetFingerprintRateLimiterId(), fake_id);
}

// Fixture that helps to read/manipulate the USS flatbuffer's internals using
// the flatbuffer C++ bindings.
class UserSecretStashInternalsTest : public UserSecretStashTest {
 protected:
  void SetUp() override {
    ASSERT_NO_FATAL_FAILURE(UserSecretStashTest::SetUp());
    ASSERT_NO_FATAL_FAILURE(UpdateBindingStrusts());
  }

  // Populates |uss_container_struct_| and |uss_payload_struct_| based on
  // |stash_|.
  void UpdateBindingStrusts() {
    // Encrypt the USS.
    CryptohomeStatusOr<brillo::Blob> uss_container =
        stash_->GetEncryptedContainer(kMainKey);
    ASSERT_TRUE(uss_container.ok());

    // Unpack the wrapped USS flatbuffer to |uss_container_struct_|.
    std::optional<UserSecretStashContainer> uss_container_struct =
        UserSecretStashContainer::Deserialize(uss_container.value());
    ASSERT_TRUE(uss_container_struct);
    uss_container_struct_ = std::move(uss_container_struct.value());

    // Decrypt and unpack the USS flatbuffer to |uss_payload_struct_|.
    brillo::SecureBlob uss_payload;
    ASSERT_TRUE(AesGcmDecrypt(
        brillo::SecureBlob(uss_container_struct_.ciphertext),
        /*ad=*/std::nullopt, brillo::SecureBlob(uss_container_struct_.gcm_tag),
        kMainKey, brillo::SecureBlob(uss_container_struct_.iv), &uss_payload));
    std::optional<UserSecretStashPayload> uss_payload_struct =
        UserSecretStashPayload::Deserialize(uss_payload);
    ASSERT_TRUE(uss_payload_struct);
    uss_payload_struct_ = std::move(*uss_payload_struct);
  }

  // Converts |uss_container_struct_| => "container flatbuffer".
  brillo::Blob GetFlatbufferFromUssContainerStruct() const {
    std::optional<brillo::Blob> serialized = uss_container_struct_.Serialize();
    if (!serialized.has_value()) {
      ADD_FAILURE() << "Failed to serialize UserSecretStashContainer";
      return brillo::Blob();
    }
    return serialized.value();
  }

  // Converts |uss_payload_struct_| => "payload flatbuffer" =>
  // UserSecretStashContainer => "container flatbuffer".
  brillo::Blob GetFlatbufferFromUssPayloadStruct() const {
    return GetFlatbufferFromUssPayloadBlob(PackUssPayloadStruct());
  }

  // Converts |uss_payload_struct_| => "payload flatbuffer".
  brillo::SecureBlob PackUssPayloadStruct() const {
    std::optional<brillo::SecureBlob> serialized =
        uss_payload_struct_.Serialize();
    if (!serialized.has_value()) {
      ADD_FAILURE() << "Failed to serialize UserSecretStashPayload";
      return brillo::SecureBlob();
    }
    return serialized.value();
  }

  // Converts "payload flatbuffer" => UserSecretStashContainer => "container
  // flatbuffer".
  brillo::Blob GetFlatbufferFromUssPayloadBlob(
      const brillo::SecureBlob& uss_payload) const {
    // Encrypt the packed |uss_payload_struct_|.
    brillo::SecureBlob iv, tag, ciphertext;
    EXPECT_TRUE(AesGcmEncrypt(uss_payload, /*ad=*/std::nullopt, kMainKey, &iv,
                              &tag, &ciphertext));

    // Create a copy of |uss_container_struct_|, with the encrypted blob
    // replaced.
    UserSecretStashContainer new_uss_container_struct = uss_container_struct_;
    new_uss_container_struct.ciphertext =
        brillo::Blob(ciphertext.begin(), ciphertext.end());
    new_uss_container_struct.iv = brillo::Blob(iv.begin(), iv.end());
    new_uss_container_struct.gcm_tag = brillo::Blob(tag.begin(), tag.end());

    // Pack |new_uss_container_struct|.
    std::optional<brillo::Blob> serialized =
        new_uss_container_struct.Serialize();
    if (!serialized.has_value()) {
      ADD_FAILURE() << "Failed to seralize the USS container";
      return brillo::Blob();
    }
    return serialized.value();
  }

  UserSecretStashContainer uss_container_struct_;
  UserSecretStashPayload uss_payload_struct_;
};

// Verify that the test fixture correctly generates the USS flatbuffers from the
// binding structs.
TEST_F(UserSecretStashInternalsTest, SmokeTest) {
  EXPECT_TRUE(
      UserSecretStash::FromEncryptedContainer(
          GetFlatbufferFromUssPayloadBlob(PackUssPayloadStruct()), kMainKey)
          .ok());
  EXPECT_TRUE(UserSecretStash::FromEncryptedContainer(
                  GetFlatbufferFromUssPayloadStruct(), kMainKey)
                  .ok());
  EXPECT_TRUE(UserSecretStash::FromEncryptedContainer(
                  GetFlatbufferFromUssContainerStruct(), kMainKey)
                  .ok());
}

// Test that decryption fails when the USS payload is a corrupted flatbuffer.
// Normally this never occurs, but we verify to be resilient against accidental
// or intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorBadPayload) {
  brillo::SecureBlob uss_payload = PackUssPayloadStruct();
  for (uint8_t& byte : uss_payload)
    byte ^= 1;

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssPayloadBlob(uss_payload), kMainKey)
                   .ok());
}

// Test that decryption fails when the USS payload is a truncated flatbuffer.
// Normally this never occurs, but we verify to be resilient against accidental
// or intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorPayloadBadSize) {
  brillo::SecureBlob uss_payload = PackUssPayloadStruct();
  uss_payload.resize(uss_payload.size() / 2);

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssPayloadBlob(uss_payload), kMainKey)
                   .ok());
}

// Test that decryption fails when the encryption algorithm is not set. Normally
// this never occurs, but we verify to be resilient against accidental or
// intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoAlgorithm) {
  uss_container_struct_.encryption_algorithm.reset();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test that decryption fails when the encryption algorithm is unknown. Normally
// this never occurs, but we verify to be resilient against accidental or
// intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorUnknownAlgorithm) {
  uss_container_struct_
      .encryption_algorithm = static_cast<UserSecretStashEncryptionAlgorithm>(
      std::numeric_limits<
          std::underlying_type_t<UserSecretStashEncryptionAlgorithm>>::max());

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test that decryption fails when the ciphertext field is missing. Normally
// this never occurs, but we verify to be resilient against accidental or
// intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoCiphertext) {
  uss_container_struct_.ciphertext.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test that decryption fails when the ciphertext field is corrupted. Normally
// this never occurs, but we verify to be resilient against accidental or
// intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorCorruptedCiphertext) {
  for (uint8_t& byte : uss_container_struct_.ciphertext)
    byte ^= 1;

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test that decryption fails when the iv field is missing. Normally this never
// occurs, but we verify to be resilient against accidental or intentional file
// corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoIv) {
  uss_container_struct_.iv.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test that decryption fails when the iv field has a wrong value. Normally this
// never occurs, but we verify to be resilient against accidental or intentional
// file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorWrongIv) {
  uss_container_struct_.iv[0] ^= 1;

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test that decryption fails when the iv field is of a wrong size. Normally
// this never occurs, but we verify to be resilient against accidental or
// intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorIvBadSize) {
  uss_container_struct_.iv.resize(uss_container_struct_.iv.size() - 1);

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test that decryption fails when the gcm_tag field is missing. Normally this
// never occurs, but we verify to be resilient against accidental or intentional
// file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoGcmTag) {
  uss_container_struct_.gcm_tag.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test that decryption fails when the gcm_tag field has a wrong value.
TEST_F(UserSecretStashInternalsTest, DecryptErrorWrongGcmTag) {
  uss_container_struct_.gcm_tag[0] ^= 1;

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test that decryption fails when the gcm_tag field is of a wrong size.
// Normally this never occurs, but we verify to be resilient against accidental
// or intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorGcmTagBadSize) {
  uss_container_struct_.gcm_tag.resize(uss_container_struct_.gcm_tag.size() -
                                       1);

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssContainerStruct(), kMainKey)
                   .ok());
}

// Test the decryption fails when the payload's FEK field is missing. Normally
// this never occurs, but we verify to be resilient against accidental or
// intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoFek) {
  uss_payload_struct_.fek.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssPayloadStruct(), kMainKey)
                   .ok());
}

// Test the decryption fails when the payload's FNEK field is missing. Normally
// this never occurs, but we verify to be resilient against accidental or
// intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoFnek) {
  uss_payload_struct_.fnek.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssPayloadStruct(), kMainKey)
                   .ok());
}

// Test the decryption fails when the payload's FEK salt field is missing.
// Normally this never occurs, but we verify to be resilient against accidental
// or intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoFekSalt) {
  uss_payload_struct_.fek_salt.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssPayloadStruct(), kMainKey)
                   .ok());
}

// Test the decryption fails when the payload's FNEK salt field is missing.
// Normally this never occurs, but we verify to be resilient against accidental
// or intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoFnekSalt) {
  uss_payload_struct_.fnek_salt.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssPayloadStruct(), kMainKey)
                   .ok());
}

// Test the decryption fails when the payload's FEK signature field is missing.
// Normally this never occurs, but we verify to be resilient against accidental
// or intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoFekSig) {
  uss_payload_struct_.fek_sig.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssPayloadStruct(), kMainKey)
                   .ok());
}

// Test the decryption fails when the payload's FNEK signature field is missing.
// Normally this never occurs, but we verify to be resilient against accidental
// or intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoFnekSig) {
  uss_payload_struct_.fnek_sig.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssPayloadStruct(), kMainKey)
                   .ok());
}

// Test the decryption fails when the payload's Chaps key field is missing.
// Normally this never occurs, but we verify to be resilient against accidental
// or intentional file corruption.
TEST_F(UserSecretStashInternalsTest, DecryptErrorNoChapsKey) {
  uss_payload_struct_.chaps_key.clear();

  EXPECT_FALSE(UserSecretStash::FromEncryptedContainer(
                   GetFlatbufferFromUssPayloadStruct(), kMainKey)
                   .ok());
}

// Fixture that prebundles the USS object with a wrapped key block.
class UserSecretStashInternalsWrappingTest
    : public UserSecretStashInternalsTest {
 protected:
  const char* const kWrappingId = "id";
  const brillo::SecureBlob kWrappingKey =
      brillo::SecureBlob(kAesGcm256KeySize, 0xB);

  void SetUp() override {
    ASSERT_NO_FATAL_FAILURE(UserSecretStashInternalsTest::SetUp());
    EXPECT_TRUE(stash_
                    ->AddWrappedMainKey(kMainKey, kWrappingId, kWrappingKey,
                                        OverwriteExistingKeyBlock::kDisabled)
                    .ok());
    ASSERT_NO_FATAL_FAILURE(UpdateBindingStrusts());
  }
};

// Verify that the test fixture correctly generates the flatbuffers from the
// Object API.
TEST_F(UserSecretStashInternalsWrappingTest, SmokeTest) {
  brillo::SecureBlob main_key;
  EXPECT_TRUE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                  GetFlatbufferFromUssContainerStruct(), kWrappingId,
                  kWrappingKey, &main_key)
                  .ok());
  EXPECT_EQ(main_key, kMainKey);
}

// Test that decryption via wrapping key fails when the only block's wrapping_id
// is empty. Normally this never occurs, but we verify to be resilient against
// accidental or intentional file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorNoWrappingId) {
  uss_container_struct_.wrapped_key_blocks[0].wrapping_id = std::string();

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key succeeds despite having an extra block
// with an empty wrapping_id (this block should be ignored). Normally this never
// occurs, but we verify to be resilient against accidental or intentional file
// corruption.
TEST_F(UserSecretStashInternalsWrappingTest, SuccessWithExtraNoWrappingId) {
  UserSecretStashWrappedKeyBlock key_block_clone =
      uss_container_struct_.wrapped_key_blocks[0];
  key_block_clone.wrapping_id = std::string();
  uss_container_struct_.wrapped_key_blocks.push_back(key_block_clone);

  brillo::SecureBlob main_key;
  EXPECT_TRUE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                  GetFlatbufferFromUssContainerStruct(), kWrappingId,
                  kWrappingKey, &main_key)
                  .ok());
}

// Test that decryption via wrapping key succeeds despite having an extra block
// with a duplicate wrapping_id (this block should be ignored). Normally this
// never occurs, but we verify to be resilient against accidental or intentional
// file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, SuccessWithDuplicateWrappingId) {
  UserSecretStashWrappedKeyBlock key_block_clone =
      uss_container_struct_.wrapped_key_blocks[0];
  uss_container_struct_.wrapped_key_blocks.push_back(key_block_clone);

  brillo::SecureBlob main_key;
  EXPECT_TRUE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                  GetFlatbufferFromUssContainerStruct(), kWrappingId,
                  kWrappingKey, &main_key)
                  .ok());
}

// Test that decryption via wrapping key fails when the algorithm is not
// specified in the stored block. Normally this never occurs, but we verify to
// be resilient against accidental or intentional file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorNoAlgorithm) {
  uss_container_struct_.wrapped_key_blocks[0].encryption_algorithm =
      std::nullopt;

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key fails when the algorithm is unknown.
// Normally this never occurs, but we verify to be resilient against accidental
// or intentional file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorUnknownAlgorithm) {
  uss_container_struct_.wrapped_key_blocks[0]
      .encryption_algorithm = static_cast<UserSecretStashEncryptionAlgorithm>(
      std::numeric_limits<
          std::underlying_type_t<UserSecretStashEncryptionAlgorithm>>::max());

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key fails when the encrypted_key is empty
// in the stored block.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorEmptyEncryptedKey) {
  uss_container_struct_.wrapped_key_blocks[0].encrypted_key.clear();

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key fails when the encrypted_key in the
// stored block is corrupted.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorBadEncryptedKey) {
  uss_container_struct_.wrapped_key_blocks[0].encrypted_key[0] ^= 1;

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key fails when the iv is empty in the
// stored block. Normally this never occurs, but we verify to be resilient
// against accidental or intentional file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorNoIv) {
  uss_container_struct_.wrapped_key_blocks[0].iv.clear();

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key fails when the iv in the stored block
// is corrupted. Normally this never occurs, but we verify to be resilient
// against accidental or intentional file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorWrongIv) {
  uss_container_struct_.wrapped_key_blocks[0].iv[0] ^= 1;

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key fails when the iv in the stored block
// is of wrong size. Normally this never occurs, but we verify to be resilient
// against accidental or intentional file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorIvBadSize) {
  uss_container_struct_.wrapped_key_blocks[0].iv.resize(
      uss_container_struct_.wrapped_key_blocks[0].iv.size() - 1);

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key fails when the gcm_tag is empty in the
// stored block. Normally this never occurs, but we verify to be resilient
// against accidental or intentional file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorNoGcmTag) {
  uss_container_struct_.wrapped_key_blocks[0].gcm_tag.clear();

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key fails when the gcm_tag in the stored
// block is corrupted. Normally this never occurs, but we verify to be resilient
// against accidental or intentional file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorWrongGcmTag) {
  uss_container_struct_.wrapped_key_blocks[0].gcm_tag[0] ^= 1;

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

// Test that decryption via wrapping key fails when the gcm_tag in the stored
// block is of wrong size. Normally this never occurs, but we verify to be
// resilient against accidental or intentional file corruption.
TEST_F(UserSecretStashInternalsWrappingTest, ErrorGcmTagBadSize) {
  uss_container_struct_.wrapped_key_blocks[0].gcm_tag.resize(
      uss_container_struct_.wrapped_key_blocks[0].gcm_tag.size() - 1);

  brillo::SecureBlob main_key;
  EXPECT_FALSE(UserSecretStash::FromEncryptedContainerWithWrappingKey(
                   GetFlatbufferFromUssContainerStruct(), kWrappingId,
                   kWrappingKey, &main_key)
                   .ok());
}

}  // namespace cryptohome
