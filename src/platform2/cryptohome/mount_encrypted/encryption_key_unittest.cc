// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mount_encrypted/encryption_key.h"

#include <memory>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include <openssl/sha.h>

#include <vboot/tlcl.h>

#include <gtest/gtest.h>

#include "cryptohome/mount_encrypted/mount_encrypted_metrics.h"
#include "cryptohome/mount_encrypted/tlcl_stub.h"
#include "cryptohome/mount_encrypted/tpm.h"

namespace mount_encrypted {
namespace {

// Size of the encryption key (256 bit AES) in bytes.
const size_t kEncryptionKeySize = 32;

// This is the constant size of the encrypted form of an encryption key, when
// encrypted with the system key, using 256 bit AES-CBC encryption. Even though
// the size of the key we encrypt is always 32 bytes, we use the standard
// padding scheme for data of variable length, which adds one padding block in
// addition two the initial two blocks containing the key material.
const size_t kWrappedKeySize = 48;

#if USE_TPM2

const uint32_t kEncStatefulAttributesTpm2 =
    TPMA_NV_AUTHWRITE | TPMA_NV_AUTHREAD | TPMA_NV_WRITEDEFINE |
    TPMA_NV_READ_STCLEAR | TPMA_NV_WRITTEN;

const uint8_t kPCRBootModeValue[] = {
    0x89, 0xea, 0xf3, 0x51, 0x34, 0xb4, 0xb3, 0xc6, 0x49, 0xf4, 0x4c,
    0x0c, 0x76, 0x5b, 0x96, 0xae, 0xab, 0x8b, 0xb3, 0x4e, 0xe8, 0x3c,
    0xc7, 0xa6, 0x83, 0xc4, 0xe5, 0x3d, 0x15, 0x81, 0xc8, 0xc7,
};

// NVRAM space contents used in tests that exercise behavior with existing
// valid NVRAM space contents. Contains a random system key.
const uint8_t kEncStatefulTpm2Contents[] = {
    0x32, 0x4D, 0x50, 0x54, 0x01, 0x00, 0x00, 0x00, 0xa3, 0xea,
    0xd7, 0x78, 0xa6, 0xb4, 0x74, 0xd7, 0x8f, 0xa1, 0x9a, 0xbd,
    0x04, 0x6a, 0xc5, 0x6c, 0x21, 0xc7, 0x60, 0x1c, 0x45, 0xe3,
    0x06, 0xe2, 0x6a, 0x68, 0x94, 0x96, 0x8b, 0x1a, 0xf3, 0x67,
};

// A random encryption key used in tests that exercise existing keys.
const uint8_t kEncryptionKeyEncStatefulTpm2[] = {
    0x7c, 0xdd, 0x2f, 0xba, 0x4b, 0x6d, 0x28, 0x5b, 0xa0, 0x5a, 0xa5,
    0x84, 0x82, 0x41, 0x02, 0x36, 0x7a, 0x17, 0xc6, 0xe4, 0x78, 0x0e,
    0x86, 0x50, 0x6c, 0x09, 0x50, 0x5c, 0x33, 0x57, 0x19, 0xae,
};

// This is kEncryptionKeyEncStatefulTpm2, encrypted with the system key from
// kEncStatefulTpm2Contents.
const uint8_t kWrappedKeyEncStatefulTpm2[] = {
    0xf4, 0xb0, 0x45, 0xc6, 0x24, 0xf8, 0xcd, 0x92, 0xb4, 0x74, 0x9c, 0x2f,
    0x45, 0x5e, 0x23, 0x8b, 0xba, 0xde, 0x67, 0x3b, 0x10, 0x3f, 0x74, 0xf1,
    0x60, 0x64, 0xa2, 0xca, 0x79, 0xce, 0xed, 0xa7, 0x04, 0xd1, 0xa5, 0x06,
    0x80, 0xc5, 0x84, 0xed, 0x34, 0x93, 0xb1, 0x44, 0xa2, 0x0a, 0x4a, 0x3e,
};

#else  // USE_TPM2

const uint32_t kEncStatefulAttributesTpm1 =
    TPM_NV_PER_WRITE_STCLEAR | TPM_NV_PER_READ_STCLEAR;
const uint32_t kLockboxAttributesTpm1 = TPM_NV_PER_WRITEDEFINE;

const uint8_t kPCRBootModeValue[] = {
    0x06, 0x4a, 0xec, 0x9b, 0xbd, 0x94, 0xde, 0xa1, 0x23, 0x1a,
    0xe7, 0x57, 0x67, 0x64, 0x7f, 0x09, 0x8c, 0x39, 0x8e, 0x79,
};

// NVRAM space contents used in tests that exercise behavior with existing
// valid NVRAM space contents. This contains a random "lockbox salt", which
// doubles as the system key for TPM 1.2 devices.
const uint8_t kLockboxV2Contents[] = {
    0x00, 0x00, 0x00, 0x02, 0x00, 0xfa, 0x33, 0x18, 0x5b, 0x57, 0x64, 0x83,
    0x57, 0x9a, 0xaa, 0xab, 0xef, 0x1e, 0x39, 0xa3, 0xa1, 0xb9, 0x94, 0xc5,
    0xc9, 0xa8, 0xd9, 0x32, 0xb4, 0xfb, 0x65, 0xb2, 0x5f, 0xb8, 0x60, 0xb8,
    0xfb, 0x94, 0xf4, 0x77, 0xad, 0x53, 0x46, 0x2e, 0xec, 0x13, 0x4a, 0x95,
    0x4a, 0xb8, 0x12, 0x2a, 0xdd, 0xd8, 0xb0, 0xc9, 0x9d, 0xd0, 0x0c, 0x06,
    0x51, 0x12, 0xcc, 0x72, 0x4d, 0x7c, 0x59, 0xb5, 0xe6,
};

// A random encryption key used in tests that exercise existing keys.
const uint8_t kEncryptionKeyLockboxV2[] = {
    0xfa, 0x33, 0x18, 0x5b, 0x57, 0x64, 0x83, 0x57, 0x9a, 0xaa, 0xab,
    0xef, 0x1e, 0x39, 0xa3, 0xa1, 0xb9, 0x94, 0xc5, 0xc9, 0xa8, 0xd9,
    0x32, 0xb4, 0xfb, 0x65, 0xb2, 0x5f, 0xb8, 0x60, 0xb8, 0xfb,
};

// This is kEncryptionKeyLockboxV2, encrypted with the system key from
// kLockboxV2Contents.
const uint8_t kWrappedKeyLockboxV2[] = {
    0x2e, 0x62, 0x9c, 0x5b, 0x32, 0x2f, 0xb4, 0xa6, 0xba, 0x72, 0xb5, 0xf4,
    0x19, 0x2a, 0xe0, 0xd6, 0xdf, 0x56, 0xf7, 0x64, 0xa0, 0xd6, 0x51, 0xe0,
    0xc1, 0x46, 0x85, 0x80, 0x41, 0xbd, 0x41, 0xab, 0xbf, 0x56, 0x32, 0xaa,
    0xe8, 0x04, 0x5b, 0x69, 0xd4, 0x23, 0x8d, 0x99, 0x84, 0xff, 0x20, 0xc3,
};

// A random encryption key used in tests that exercise the situation where NVRAM
// space is missing and we fall back to writing the encryption key to disk.
const uint8_t kEncryptionKeyNeedsFinalization[] = {
    0xa4, 0x46, 0x75, 0x14, 0x38, 0x66, 0x83, 0x14, 0x2f, 0x88, 0x03,
    0x31, 0x0c, 0x13, 0x47, 0x6a, 0x52, 0x78, 0xcd, 0xff, 0xb9, 0x9c,
    0x99, 0x9e, 0x30, 0x0b, 0x79, 0xf7, 0xad, 0x34, 0x2f, 0xb0,
};

// This is kEncryptionKeyNeedsFinalization, obfuscated by encrypting it with a
// well-known hard-coded system key (the SHA-256 hash of "needs finalization").
const uint8_t kWrappedKeyNeedsFinalization[] = {
    0x38, 0x38, 0x9e, 0x59, 0x39, 0x88, 0xae, 0xb8, 0x74, 0xe8, 0x14, 0x58,
    0x78, 0x12, 0x1b, 0xb1, 0xf4, 0x70, 0xb9, 0x0f, 0x76, 0x22, 0x97, 0xe6,
    0x43, 0x21, 0x59, 0x0f, 0x36, 0x86, 0x90, 0x74, 0x23, 0x7f, 0x14, 0xd1,
    0x3d, 0xef, 0x01, 0x92, 0x9c, 0x89, 0x15, 0x85, 0xc5, 0xe5, 0x78, 0x10,
};

// Contents of the encstateful TPM NVRAM space used in tests that set up
// existing valid NVRAM space contents. Contains random system key material.
const uint8_t kEncStatefulTpm1Contents[] = {
    0x31, 0x4D, 0x50, 0x54, 0x01, 0x01, 0x00, 0x00, 0xa3, 0xea, 0xd7, 0x78,
    0xa6, 0xb4, 0x74, 0xd7, 0x8f, 0xa1, 0x9a, 0xbd, 0x04, 0x6a, 0xc5, 0x6c,
    0x21, 0xc7, 0x60, 0x1c, 0x45, 0xe3, 0x06, 0xe2, 0x6a, 0x68, 0x94, 0x96,
    0x8b, 0x1a, 0xf3, 0x67, 0xf1, 0x4c, 0x52, 0xf9, 0x34, 0xf0, 0xf2, 0xeb,
    0xcb, 0xce, 0x2f, 0xb3, 0xb3, 0x63, 0xb3, 0x67, 0x75, 0x75, 0xdc, 0x5d,
    0x0e, 0xcb, 0xcd, 0x4b, 0x44, 0xf9, 0x20, 0x49, 0x42, 0x4d, 0x22, 0x96,
};

// Contents of the encstateful TPM NVRAM space used in tests that set up
// existing writable NVRAM space contents.
const uint8_t kEncStatefulTpm1ContentsAllZeros[] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

// Contents of the encstateful TPM NVRAM space used in tests that set up
// existing writable NVRAM space contents.
const uint8_t kEncStatefulTpm1ContentsAllOnes[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

// A random encryption key used in tests that exercise the situation where the
// encstateful NVRAM space already exists.
const uint8_t kEncryptionKeyEncStatefulTpm1[] = {
    0x7c, 0xdd, 0x2f, 0xba, 0x4b, 0x6d, 0x28, 0x5b, 0xa0, 0x5a, 0xa5,
    0x84, 0x82, 0x41, 0x02, 0x36, 0x7a, 0x17, 0xc6, 0xe4, 0x78, 0x0e,
    0x86, 0x50, 0x6c, 0x09, 0x50, 0x5c, 0x33, 0x57, 0x19, 0xae,
};

// This is kEncryptionKeyEncStatefulTpm1, encrypted with the system key from
// kEncStatefulTpm1Contents.
const uint8_t kWrappedKeyEncStatefulTpm1[] = {
    0x7d, 0x10, 0x2a, 0x73, 0x20, 0xd2, 0x29, 0xe8, 0x27, 0xeb, 0xfd, 0xc0,
    0x57, 0xd8, 0x03, 0x16, 0x3c, 0xb7, 0x00, 0x80, 0x56, 0xf9, 0x93, 0x84,
    0xb6, 0xb7, 0xcb, 0xfb, 0x42, 0x59, 0x2b, 0x07, 0xd5, 0x00, 0xa4, 0x8d,
    0x9c, 0x70, 0x9d, 0x15, 0x80, 0xe3, 0x75, 0xea, 0x7b, 0x72, 0x9c, 0xe8,
};

#endif  // !USE_TPM2

}  // namespace

using SystemKeyStatus = EncryptionKey::SystemKeyStatus;
using EncryptionKeyStatus = EncryptionKey::EncryptionKeyStatus;

class EncryptionKeyTest : public testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    ASSERT_TRUE(base::CreateDirectory(
        tmpdir_.GetPath().AppendASCII("mnt/stateful_partition")));
    ASSERT_TRUE(base::CreateDirectory(
        tmpdir_.GetPath().AppendASCII(paths::cryptohome::kTpmOwned).DirName()));

    metrics_singleton_ = std::make_unique<ScopedMountEncryptedMetricsSingleton>(
        tmpdir_.GetPath().AppendASCII("metrics").value());

    ClearTPM();
    ResetLoader();
  }

  void TearDown() override { ASSERT_EQ(tlcl_.GetDictionaryAttackCounter(), 0); }

  void ResetLoader() {
    tpm_ = std::make_unique<Tpm>();
    loader_ = SystemKeyLoader::Create(tpm_.get(), tmpdir_.GetPath());
    key_ = std::make_unique<EncryptionKey>(loader_.get(), tmpdir_.GetPath());
  }

  void ResetTPM() {
    tlcl_.Reset();
    tlcl_.SetPCRValue(kPCRBootMode, kPCRBootModeValue);
  }

  void ClearTPM() {
    tlcl_.Clear();
    ResetTPM();
  }

  void SetOwned() {
    tlcl_.SetOwned({0x5e, 0xc2, 0xe7});
    if (!USE_TPM2) {
      ASSERT_TRUE(base::WriteFile(
          tmpdir_.GetPath().AppendASCII(paths::cryptohome::kTpmOwned), ""));
    }
  }

  void SetupSpace(uint32_t index,
                  uint32_t attributes,
                  bool bind_to_pcr0,
                  const uint8_t* data,
                  size_t size) {
    TlclStub::NvramSpaceData* space = tlcl_.GetSpace(index);
    space->contents.assign(data, data + size);
    space->attributes = attributes;

    if (bind_to_pcr0) {
      uint32_t policy_size = SHA256_DIGEST_LENGTH;
      space->policy.resize(policy_size);
      uint8_t pcr_values[1][TPM_PCR_DIGEST] = {};
      memcpy(pcr_values[0], kPCRBootModeValue, TPM_PCR_DIGEST);
      ASSERT_EQ(TPM_SUCCESS,
                TlclInitNvAuthPolicy((1 << kPCRBootMode), pcr_values,
                                     space->policy.data(), &policy_size));
    }
  }

  void WriteWrappedKey(const base::FilePath& path, const uint8_t* key) {
    ASSERT_TRUE(base::CreateDirectory(path.DirName()));
    ASSERT_TRUE(base::WriteFile(path, reinterpret_cast<const char*>(key),
                                kWrappedKeySize));
  }

  void RequestPreservation() {
    ASSERT_TRUE(
        base::File(key_->preservation_request_path(),
                   base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE)
            .IsValid());
  }

  void SetupPendingFirmwareUpdate(bool available, int exit_status) {
    // Put the firmware update request into place.
    base::FilePath update_request_path(
        tmpdir_.GetPath().AppendASCII(paths::kFirmwareUpdateRequest));
    ASSERT_TRUE(base::CreateDirectory(update_request_path.DirName()));
    base::File update_request_file(
        update_request_path,
        base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
    ASSERT_TRUE(update_request_file.IsValid());

    // Create a placeholder firmware update image file.
    base::FilePath firmware_update_image_path;
    if (available) {
      firmware_update_image_path = tmpdir_.GetPath()
                                       .AppendASCII(paths::kFirmwareDir)
                                       .AppendASCII("placeholder_fw.bin");
      ASSERT_TRUE(base::CreateDirectory(firmware_update_image_path.DirName()));
      base::File firmware_update_image_file(
          firmware_update_image_path,
          base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
      ASSERT_TRUE(firmware_update_image_file.IsValid());
    }

    // Set up a shell script to simulate the update locator tool.
    std::string script = base::StringPrintf(
        "#!/bin/sh\necho \"%s\"\nexit %d",
        firmware_update_image_path.value().c_str(), exit_status);
    base::FilePath firmware_update_locator_path =
        tmpdir_.GetPath().AppendASCII(paths::kFirmwareUpdateLocator);
    ASSERT_TRUE(base::CreateDirectory(firmware_update_locator_path.DirName()));
    ASSERT_TRUE(base::WriteFile(firmware_update_locator_path, script.data(),
                                script.size()));
    ASSERT_TRUE(
        base::SetPosixFilePermissions(firmware_update_locator_path, 0755));
  }

  void ExpectNeedsFinalization() {
    EXPECT_FALSE(key_->did_finalize());
    EXPECT_TRUE(base::PathExists(key_->needs_finalization_path()));
    EXPECT_FALSE(base::PathExists(key_->key_path()));
  }

  void ExpectFinalized(bool did_finalize_expectation) {
    EXPECT_EQ(did_finalize_expectation, key_->did_finalize());
    EXPECT_FALSE(base::PathExists(key_->needs_finalization_path()));
    EXPECT_TRUE(base::PathExists(key_->key_path()));
  }

  void ExpectSystemKeyFailed() {
    EXPECT_EQ(key_->LoadChromeOSSystemKey(), RESULT_FAIL_FATAL);
  }

  void ExpectFreshKey() {
    EXPECT_EQ(key_->LoadChromeOSSystemKey(), RESULT_SUCCESS);
    EXPECT_EQ(key_->LoadEncryptionKey(), RESULT_SUCCESS);
    EXPECT_EQ(key_->encryption_key().size(), kEncryptionKeySize);
    EXPECT_TRUE(key_->is_fresh());
  }

  void ExpectExistingKey(const uint8_t* expected_key) {
    EXPECT_EQ(key_->LoadChromeOSSystemKey(), RESULT_SUCCESS);
    EXPECT_EQ(key_->LoadEncryptionKey(), RESULT_SUCCESS);
    EXPECT_EQ(key_->encryption_key().size(), kEncryptionKeySize);
    if (expected_key) {
      EXPECT_EQ(
          brillo::SecureBlob(expected_key, expected_key + kEncryptionKeySize),
          key_->encryption_key());
    }
    EXPECT_FALSE(key_->is_fresh());
  }

  void ExpectLockboxValid(bool valid_expected) {
    bool valid_actual = !valid_expected;
    EXPECT_EQ(RESULT_SUCCESS, loader_->CheckLockbox(&valid_actual));
    EXPECT_EQ(valid_expected, valid_actual);
  }

  void CheckSpace(uint32_t index, uint32_t attributes, uint32_t size) {
    TlclStub::NvramSpaceData* space = tlcl_.GetSpace(index);
    EXPECT_EQ(attributes, space->attributes);
    EXPECT_EQ(size, space->contents.size());
    EXPECT_TRUE(space->read_locked);
    EXPECT_TRUE(space->write_locked);
  }

#if !USE_TPM2
  void CheckLockboxTampering() {
    ResetTPM();

    // Set up invalid lockbox space contents and perform another load. Verify
    // that the lockbox space is flagged invalid afterwards.
    SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
               sizeof(kLockboxV2Contents) - 1);

    ResetLoader();
    key_->LoadChromeOSSystemKey();
    key_->LoadEncryptionKey();
    ExpectLockboxValid(false);
  }

  void SetStaleOwnershipFlag() {
    ASSERT_TRUE(base::WriteFile(
        tmpdir_.GetPath().AppendASCII(paths::cryptohome::kTpmOwned), ""));
  }

#endif

  base::ScopedTempDir tmpdir_;
  TlclStub tlcl_;

  std::unique_ptr<Tpm> tpm_;
  std::unique_ptr<SystemKeyLoader> loader_;
  std::unique_ptr<EncryptionKey> key_;

  std::unique_ptr<ScopedMountEncryptedMetricsSingleton> metrics_singleton_;
};

#if USE_TPM2

TEST_F(EncryptionKeyTest, TpmClearNoSpaces) {
  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, kEncStatefulSize);
}

TEST_F(EncryptionKeyTest, TpmOwnedNoSpaces) {
  SetOwned();

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectNeedsFinalization();
  EXPECT_EQ(SystemKeyStatus::kFinalizationPending, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, TpmExistingSpaceNoKeyFile) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, false,
             kEncStatefulTpm2Contents, sizeof(kEncStatefulTpm2Contents));

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, kEncStatefulSize);
}

TEST_F(EncryptionKeyTest, TpmExistingSpaceBadKey) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, false,
             kEncStatefulTpm2Contents, sizeof(kEncStatefulTpm2Contents));
  std::vector<uint8_t> wrapped_key(sizeof(kWrappedKeyEncStatefulTpm2), 0xa5);
  WriteWrappedKey(key_->key_path(), wrapped_key.data());

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, kEncStatefulSize);
}

TEST_F(EncryptionKeyTest, TpmExistingSpaceBadAttributes) {
  uint32_t attributes = kEncStatefulAttributesTpm2 | TPMA_NV_PLATFORMCREATE;
  SetupSpace(kEncStatefulIndex, attributes, false, kEncStatefulTpm2Contents,
             sizeof(kEncStatefulTpm2Contents));
  WriteWrappedKey(key_->key_path(), kWrappedKeyEncStatefulTpm2);

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectNeedsFinalization();
  EXPECT_EQ(SystemKeyStatus::kFinalizationPending, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, TpmExistingSpaceNotYetWritten) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2 & ~TPMA_NV_WRITTEN,
             false, kEncStatefulTpm2Contents, sizeof(kEncStatefulTpm2Contents));

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, kEncStatefulSize);
}

TEST_F(EncryptionKeyTest, TpmExistingSpaceBadContents) {
  std::vector<uint8_t> bad_contents(sizeof(kEncStatefulTpm2Contents), 0xa5);
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, false,
             bad_contents.data(), bad_contents.size());

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, kEncStatefulSize);
}

TEST_F(EncryptionKeyTest, TpmExistingSpaceValid) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, false,
             kEncStatefulTpm2Contents, sizeof(kEncStatefulTpm2Contents));
  WriteWrappedKey(key_->key_path(), kWrappedKeyEncStatefulTpm2);

  ExpectExistingKey(kEncryptionKeyEncStatefulTpm2);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm2, kEncStatefulSize);
}

#else  // USE_TPM2

TEST_F(EncryptionKeyTest, TpmClearNoSpaces) {
  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, TpmOwnedNoSpaces) {
  SetOwned();

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectNeedsFinalization();
  EXPECT_EQ(SystemKeyStatus::kFinalizationPending, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, TpmClearExistingLockboxV2Unowned) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, TpmOwnedExistingLockboxV2Finalize) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  SetOwned();

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMLockbox, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, TpmOwnedExistingLockboxV2Finalized) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  SetOwned();
  WriteWrappedKey(key_->key_path(), kWrappedKeyLockboxV2);

  ExpectExistingKey(kEncryptionKeyLockboxV2);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMLockbox, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, TpmOwnedExistingLockboxV2BadDecrypt) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  SetOwned();
  std::vector<uint8_t> wrapped_key(sizeof(kWrappedKeyLockboxV2), 0xa5);
  WriteWrappedKey(key_->key_path(), wrapped_key.data());

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMLockbox, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, TpmClearNeedsFinalization) {
  WriteWrappedKey(key_->needs_finalization_path(),
                  kWrappedKeyNeedsFinalization);

  ExpectExistingKey(kEncryptionKeyNeedsFinalization);
  EXPECT_EQ(EncryptionKeyStatus::kNeedsFinalization,
            key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, TpmOwnedNeedsFinalization) {
  SetOwned();
  WriteWrappedKey(key_->needs_finalization_path(),
                  kWrappedKeyNeedsFinalization);

  ExpectExistingKey(kEncryptionKeyNeedsFinalization);
  EXPECT_EQ(EncryptionKeyStatus::kNeedsFinalization,
            key_->encryption_key_status());
  ExpectNeedsFinalization();
  EXPECT_EQ(SystemKeyStatus::kFinalizationPending, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, EncStatefulTpmClearExisting) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             kEncStatefulTpm1Contents, sizeof(kEncStatefulTpm1Contents));
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  bool initialized = false;
  EXPECT_EQ(RESULT_SUCCESS, tpm_->HasSystemKeyInitializedFlag(&initialized));
  EXPECT_TRUE(initialized);
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  ExpectLockboxValid(false);

  TlclStub::NvramSpaceData* space = tlcl_.GetSpace(kEncStatefulIndex);
  EXPECT_NE(space->contents,
            std::vector<uint8_t>(
                kEncStatefulTpm1Contents,
                kEncStatefulTpm1Contents + sizeof(kEncStatefulTpm1Contents)));
}

TEST_F(EncryptionKeyTest, TpmClearExistingLockboxV2UnownedStaleOwnershipFlag) {
  SetStaleOwnershipFlag();
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             kEncStatefulTpm1Contents, sizeof(kEncStatefulTpm1Contents));
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  bool initialized = false;
  EXPECT_EQ(RESULT_SUCCESS, tpm_->HasSystemKeyInitializedFlag(&initialized));
  EXPECT_TRUE(initialized);
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  ExpectLockboxValid(false);

  TlclStub::NvramSpaceData* space = tlcl_.GetSpace(kEncStatefulIndex);
  EXPECT_NE(space->contents,
            std::vector<uint8_t>(
                kEncStatefulTpm1Contents,
                kEncStatefulTpm1Contents + sizeof(kEncStatefulTpm1Contents)));
}

TEST_F(EncryptionKeyTest, EncStatefulTpmClearWritableAllZeros) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             kEncStatefulTpm1ContentsAllZeros,
             sizeof(kEncStatefulTpm1ContentsAllZeros));
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  bool initialized = false;
  EXPECT_EQ(RESULT_SUCCESS, tpm_->HasSystemKeyInitializedFlag(&initialized));
  EXPECT_TRUE(initialized);
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  ExpectLockboxValid(false);

  TlclStub::NvramSpaceData* space = tlcl_.GetSpace(kEncStatefulIndex);
  EXPECT_NE(space->contents,
            std::vector<uint8_t>(kEncStatefulTpm1ContentsAllZeros,
                                 kEncStatefulTpm1ContentsAllZeros +
                                     sizeof(kEncStatefulTpm1ContentsAllZeros)));
}

TEST_F(EncryptionKeyTest, EncStatefulTpmClearWritableAllOnes) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             kEncStatefulTpm1ContentsAllOnes,
             sizeof(kEncStatefulTpm1ContentsAllOnes));
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  bool initialized = false;
  EXPECT_EQ(RESULT_SUCCESS, tpm_->HasSystemKeyInitializedFlag(&initialized));
  EXPECT_TRUE(initialized);
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  ExpectLockboxValid(false);

  TlclStub::NvramSpaceData* space = tlcl_.GetSpace(kEncStatefulIndex);
  EXPECT_NE(space->contents,
            std::vector<uint8_t>(kEncStatefulTpm1ContentsAllOnes,
                                 kEncStatefulTpm1ContentsAllOnes +
                                     sizeof(kEncStatefulTpm1ContentsAllOnes)));
}

TEST_F(EncryptionKeyTest, EncStatefulTpmClearInitialized) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             kEncStatefulTpm1Contents, sizeof(kEncStatefulTpm1Contents));
  tpm_->SetSystemKeyInitializedFlag();
  WriteWrappedKey(key_->key_path(), kWrappedKeyEncStatefulTpm1);

  ExpectExistingKey(kEncryptionKeyEncStatefulTpm1);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
}

TEST_F(EncryptionKeyTest, EncStatefulTpmOwnedExisting) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             kEncStatefulTpm1Contents, sizeof(kEncStatefulTpm1Contents));
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  SetOwned();
  WriteWrappedKey(key_->key_path(), kWrappedKeyEncStatefulTpm1);

  ExpectExistingKey(kEncryptionKeyEncStatefulTpm1);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  ExpectLockboxValid(true);
  EXPECT_EQ(brillo::SecureBlob(kLockboxV2Contents,
                               kLockboxV2Contents + sizeof(kLockboxV2Contents)),
            tpm_->GetLockboxSpace()->contents());
}

TEST_F(EncryptionKeyTest, EncStatefulTpmClearBadPCRBinding) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, false,
             kEncStatefulTpm1Contents, sizeof(kEncStatefulTpm1Contents));

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, EncStatefulTpmClearBadSize) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             kEncStatefulTpm1Contents, sizeof(kEncStatefulTpm1Contents) - 1);

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, EncStatefulTpmClearBadAttributes) {
  SetupSpace(kEncStatefulIndex, 0, true, kEncStatefulTpm1Contents,
             sizeof(kEncStatefulTpm1Contents));

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
}

TEST_F(EncryptionKeyTest, EncStatefulTpmClearBadContents) {
  std::vector<uint8_t> bad_contents(sizeof(kEncStatefulTpm1Contents), 0xa5);
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             bad_contents.data(), bad_contents.size());

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
}

TEST_F(EncryptionKeyTest, EncStatefulTpmOwnedBadSpaceLockboxFallback) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, false,
             kEncStatefulTpm1Contents, sizeof(kEncStatefulTpm1Contents));
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  SetOwned();
  WriteWrappedKey(key_->key_path(), kWrappedKeyLockboxV2);

  ExpectExistingKey(kEncryptionKeyLockboxV2);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMLockbox, key_->system_key_status());
  ExpectLockboxValid(true);
}

TEST_F(EncryptionKeyTest, EncStatefulLockboxMACFailure) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             kEncStatefulTpm1Contents, sizeof(kEncStatefulTpm1Contents));
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents) - 1);
  SetOwned();
  WriteWrappedKey(key_->key_path(), kWrappedKeyEncStatefulTpm1);

  ExpectExistingKey(kEncryptionKeyEncStatefulTpm1);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  ExpectLockboxValid(false);
}

TEST_F(EncryptionKeyTest, StatefulPreservationSuccessLockbox) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  WriteWrappedKey(key_->key_path(), kWrappedKeyLockboxV2);
  RequestPreservation();
  SetupPendingFirmwareUpdate(true, EXIT_SUCCESS);

  ExpectExistingKey(kEncryptionKeyLockboxV2);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  EXPECT_TRUE(tlcl_.IsOwned());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  ExpectLockboxValid(true);

  // Perform another TPM clear and verify that a second preservation succeeds.
  ClearTPM();
  ResetLoader();
  RequestPreservation();
  SetupPendingFirmwareUpdate(false, EXIT_SUCCESS);

  ExpectExistingKey(kEncryptionKeyLockboxV2);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  ExpectLockboxValid(true);

  CheckLockboxTampering();
}

TEST_F(EncryptionKeyTest, StatefulPreservationSuccessEncstateful) {
  SetupSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, true,
             kEncStatefulTpm1Contents, sizeof(kEncStatefulTpm1Contents));
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  WriteWrappedKey(key_->key_path(), kWrappedKeyEncStatefulTpm1);
  RequestPreservation();
  SetupPendingFirmwareUpdate(true, EXIT_SUCCESS);

  ExpectExistingKey(kEncryptionKeyEncStatefulTpm1);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  ExpectLockboxValid(true);

  CheckLockboxTampering();
}

TEST_F(EncryptionKeyTest, StatefulPreservationErrorNotEligible) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  WriteWrappedKey(key_->key_path(), kWrappedKeyLockboxV2);
  RequestPreservation();
  SetupPendingFirmwareUpdate(false, EXIT_SUCCESS);

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  EXPECT_FALSE(base::PathExists(key_->preservation_request_path()));
  ExpectLockboxValid(false);
}

TEST_F(EncryptionKeyTest, StatefulPreservationErrorUpdateLocatorFailure) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  WriteWrappedKey(key_->key_path(), kWrappedKeyLockboxV2);
  RequestPreservation();
  SetupPendingFirmwareUpdate(true, EXIT_FAILURE);

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  EXPECT_FALSE(base::PathExists(key_->preservation_request_path()));
  ExpectLockboxValid(false);
}

TEST_F(EncryptionKeyTest, StatefulPreservationNoPreviousKey) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  RequestPreservation();
  SetupPendingFirmwareUpdate(true, EXIT_SUCCESS);

  ExpectFreshKey();
  EXPECT_EQ(EncryptionKeyStatus::kFresh, key_->encryption_key_status());
  ExpectFinalized(true);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  EXPECT_FALSE(base::PathExists(key_->preservation_request_path()));
}

TEST_F(EncryptionKeyTest, StatefulPreservationRetryKeyfileMove) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  WriteWrappedKey(key_->preserved_previous_key_path(), kWrappedKeyLockboxV2);
  RequestPreservation();
  SetupPendingFirmwareUpdate(true, EXIT_SUCCESS);

  ExpectExistingKey(kEncryptionKeyLockboxV2);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  EXPECT_TRUE(tlcl_.IsOwned());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  EXPECT_FALSE(base::PathExists(key_->preservation_request_path()));
}

TEST_F(EncryptionKeyTest, StatefulPreservationRetryEncryptionKeyWrapping) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  WriteWrappedKey(key_->preserved_previous_key_path(), kWrappedKeyLockboxV2);
  WriteWrappedKey(key_->key_path(), kWrappedKeyEncStatefulTpm1);
  SetupPendingFirmwareUpdate(true, EXIT_SUCCESS);

  ExpectExistingKey(kEncryptionKeyLockboxV2);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  EXPECT_TRUE(tlcl_.IsOwned());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  EXPECT_FALSE(base::PathExists(key_->preservation_request_path()));
}

TEST_F(EncryptionKeyTest, StatefulPreservationRetryTpmOwnership) {
  SetupSpace(kLockboxIndex, kLockboxAttributesTpm1, true, kLockboxV2Contents,
             sizeof(kLockboxV2Contents));
  tlcl_.SetOwned({kOwnerSecret, kOwnerSecret + kOwnerSecretSize});
  WriteWrappedKey(key_->preserved_previous_key_path(), kWrappedKeyLockboxV2);
  WriteWrappedKey(key_->key_path(), kWrappedKeyEncStatefulTpm1);
  SetupPendingFirmwareUpdate(true, EXIT_SUCCESS);

  ExpectExistingKey(kEncryptionKeyLockboxV2);
  EXPECT_EQ(EncryptionKeyStatus::kKeyFile, key_->encryption_key_status());
  ExpectFinalized(false);
  EXPECT_EQ(SystemKeyStatus::kNVRAMEncstateful, key_->system_key_status());
  EXPECT_TRUE(tlcl_.IsOwned());
  CheckSpace(kEncStatefulIndex, kEncStatefulAttributesTpm1, kEncStatefulSize);
  EXPECT_FALSE(base::PathExists(key_->preservation_request_path()));
}

#endif  // !USE_TPM2

}  // namespace mount_encrypted
