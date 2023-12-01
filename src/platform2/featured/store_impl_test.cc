// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/files/file_util.h>
#include <dbus/mock_bus.h>
#include <featured/proto_bindings/featured.pb.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <libhwsec-foundation/crypto/hmac.h>

#include "featured/store_impl.h"

namespace featured {

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;

MATCHER_P(EqualsProto,
          message,
          "Match a proto Message equal to the matcher's argument.") {
  std::string expected_serialized, actual_serialized;
  message.SerializeToString(&expected_serialized);
  arg.SerializeToString(&actual_serialized);
  return expected_serialized == actual_serialized;
}

// Arbitrary 32-byte string.
constexpr char kInitialBootKey[] = "01234567890123456789012345678901";
constexpr char kCorruptFileContent[] = "test_corrupted_data";

class StoreImplTest : public testing::Test {
 public:
  StoreImplTest()
      : mock_bus_(base::MakeRefCounted<dbus::MockBus>(dbus::Bus::Options{})) {
    EXPECT_TRUE(dir_.CreateUniqueTempDir());
    store_path_ = get_dir().Append("store");
    tpm_seed_path_ = get_dir().Append("tpm_seed");
  }

  const base::FilePath& get_dir() { return dir_.GetPath(); }

 protected:
  void SetUp() {
    ASSERT_TRUE(base::WriteFile(tpm_seed_path_, std::string(kInitialBootKey)));
  }

  void ComputeHmac(Store& store) {
    // Compute overrides HMAC.
    brillo::SecureBlob hash = hwsec_foundation::HmacSha256(
        brillo::SecureBlob(std::string(kInitialBootKey)),
        brillo::BlobFromString(store.overrides()));
    store.set_overrides_hmac(hash.to_string());
  }

  void InitializeStore(Store& store) {
    store.set_boot_attempts_since_last_seed_update(0);
    SeedDetails* seed = store.mutable_last_good_seed();
    seed->set_compressed_data("test_compressed_data");
    seed->set_date(1);
    seed->set_fetch_time(1);
    seed->set_locale("test_locale");
    seed->set_milestone(110);
    seed->set_permanent_consistency_country("us");
    seed->set_session_consistency_country("us");
    seed->set_signature("test_signature");
    OverridesSet set;
    FeatureOverride* feature = set.add_overrides();
    feature->set_name("CrOSEarlyBootTest");
    feature->set_enabled(true);
    std::string set_serialized;
    ASSERT_TRUE(set.SerializeToString(&set_serialized));
    store.set_overrides(set_serialized);

    ComputeHmac(store);
  }

  base::FilePath store_path_;
  base::FilePath tpm_seed_path_;

 private:
  base::ScopedTempDir dir_;
  scoped_refptr<dbus::MockBus> mock_bus_;
};

// Check that StoreImpl creation succeeds when the seed is too short.
TEST_F(StoreImplTest, KeyRead_BadSize) {
  // Create key that's too short.
  ASSERT_TRUE(base::WriteFile(tpm_seed_path_, "bad_length"));
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  EXPECT_NE(store_interface, nullptr);
}

// Check that StoreImpl creation succeeds when reading the seed file fails.
TEST_F(StoreImplTest, KeyRead_NonExistent) {
  ASSERT_TRUE(brillo::DeleteFile(tpm_seed_path_));
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  EXPECT_NE(store_interface, nullptr);
}

// Check that StoreImpl creation fails when reading the store file fails.
TEST_F(StoreImplTest, StoreRead_Failure) {
  // Create store with only write permission.
  base::File store_file(
      store_path_, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  ASSERT_TRUE(store_file.IsValid());
  ASSERT_TRUE(SetPosixFilePermissions(store_path_,
                                      base::FILE_PERMISSION_WRITE_BY_USER));

  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  EXPECT_EQ(store_interface, nullptr);
}

// Check that StoreImpl creation fails when store file creation fails due to
// incorrect permissions.
TEST_F(StoreImplTest, StoreCreate_Failure_WrongPermissions) {
  // Modify directory to have only read permission.
  ASSERT_TRUE(
      SetPosixFilePermissions(get_dir(), base::FILE_PERMISSION_READ_BY_USER));

  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  EXPECT_EQ(store_interface, nullptr);

  // Add execute and write permissions back to more likely to clean up the
  // directory correctly.
  ASSERT_TRUE(SetPosixFilePermissions(get_dir(),
                                      base::FILE_PERMISSION_EXECUTE_BY_USER |
                                          base::FILE_PERMISSION_WRITE_BY_USER));
}

// Check that StoreImpl creation fails when store file path is invalid (eg.
// empty path).
TEST_F(StoreImplTest, StoreCreate_Failure_InvalidPath) {
  std::unique_ptr<StoreInterface> store_interface = StoreImpl::Create(
      /*store_path=*/base::FilePath(""), tpm_seed_path_);
  EXPECT_EQ(store_interface, nullptr);
}

// Check that StoreImpl creation fails when writing to the store file fails.
TEST_F(StoreImplTest, StoreWrite_Failure) {
  // Create store with only read permission.
  base::File store_file(
      store_path_, base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE);
  ASSERT_TRUE(store_file.IsValid());
  ASSERT_TRUE(
      SetPosixFilePermissions(store_path_, base::FILE_PERMISSION_READ_BY_USER));

  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  EXPECT_EQ(store_interface, nullptr);
}

// Check that StoreImpl object is created when the store is successfully
// verified. This means reading the key, the store file, and the sig file from
// disk succeed as well.
//
// Verifies the store on disk is not modified.
TEST_F(StoreImplTest, StoreVerified_Success) {
  // Create store.
  Store store;
  InitializeStore(store);

  // Serialize store.
  std::string serialized_store;
  ASSERT_TRUE(store.SerializeToString(&serialized_store));

  // Write serialized store to disk.
  ASSERT_TRUE(base::WriteFile(store_path_, serialized_store));

  // Create StoreImpl object.
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  EXPECT_NE(store_interface, nullptr);

  std::string store_content;
  ASSERT_TRUE(ReadFileToString(store_path_, &store_content));

  EXPECT_EQ(store_content, serialized_store);
}

// Check that StoreImpl object is created when store verification fails due to
// corrupt store file. Verifies an empty overrides and associated HMAC are
// written to disk.
TEST_F(StoreImplTest, StoreCorruption_Verification_Failure) {
  // Create store.
  Store store;
  InitializeStore(store);

  // Serialize store.
  std::string serialized_store;
  ASSERT_TRUE(store.SerializeToString(&serialized_store));

  // Corrupt store.
  store.set_overrides("junk");
  std::string corrupted_store;
  ASSERT_TRUE(store.SerializeToString(&corrupted_store));

  // Write corrupted store to disk.
  ASSERT_TRUE(base::WriteFile(store_path_, corrupted_store));

  // Create StoreImpl object.
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  EXPECT_NE(store_interface, nullptr);

  // Verify that the on-disk contents are valid.
  std::string store_content;
  ASSERT_TRUE(ReadFileToString(store_path_, &store_content));

  Store actual_store;
  ASSERT_TRUE(actual_store.ParseFromString(store_content));
  EXPECT_TRUE(actual_store.overrides().empty());

  store.clear_overrides();
  ComputeHmac(store);
  EXPECT_EQ(actual_store.overrides_hmac(), store.overrides_hmac());
}

// Check that StoreImpl object is created when store verification fails due to
// corrupt HMAC field. Verifies an empty overrides and associated HMAC are
// written to disk.
TEST_F(StoreImplTest, HMACCorruption_Verification_Failure) {
  // Create store.
  Store store;
  InitializeStore(store);

  store.set_overrides_hmac("bad hmac");

  // Serialize store.
  std::string serialized_store;
  ASSERT_TRUE(store.SerializeToString(&serialized_store));

  // Write serialized store to disk.
  ASSERT_TRUE(base::WriteFile(store_path_, serialized_store));

  // Create StoreImpl object.
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  EXPECT_NE(store_interface, nullptr);

  // Verify that the on-disk contents are valid.
  std::string store_content;
  ASSERT_TRUE(ReadFileToString(store_path_, &store_content));

  Store actual_store;
  ASSERT_TRUE(actual_store.ParseFromString(store_content));
  EXPECT_TRUE(actual_store.overrides().empty());

  store.clear_overrides();
  ComputeHmac(store);
  EXPECT_EQ(actual_store.overrides_hmac(), store.overrides_hmac());
}

// Check that StoreImpl object is created when store deserialization fails due
// to corrupt store.
//
// Verifies an empty store and associated HMAC are written to disk.
TEST_F(StoreImplTest, StoreCorruption_Deserialize_Failure) {
  // Write corrupted store to disk.
  std::string corrupted_store = kCorruptFileContent;
  ASSERT_TRUE(base::WriteFile(store_path_, corrupted_store));

  // Create StoreImpl object.
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  EXPECT_NE(store_interface, nullptr);

  Store expected;
  ComputeHmac(expected);
  std::string expected_serialized;
  ASSERT_TRUE(expected.SerializeToString(&expected_serialized));

  std::string store_content;
  ASSERT_TRUE(ReadFileToString(store_path_, &store_content));
  EXPECT_EQ(store_content, expected_serialized);
}

// Check correctness of incrementing the boot attempts field in the store.
TEST_F(StoreImplTest, IncrementBootAttempts_Success) {
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  ASSERT_NE(store_interface, nullptr);

  // Check boot attempts field.
  EXPECT_EQ(store_interface->GetBootAttemptsSinceLastUpdate(), 0);

  // Increment boot attempts.
  EXPECT_TRUE(store_interface->IncrementBootAttemptsSinceLastUpdate());
  EXPECT_EQ(store_interface->GetBootAttemptsSinceLastUpdate(), 1);

  // Verify boot attempts update is reflected on disk.
  std::string store_content;
  ASSERT_TRUE(ReadFileToString(store_path_, &store_content));

  Store store;
  ASSERT_TRUE(store.ParseFromString(store_content));
  EXPECT_EQ(store.boot_attempts_since_last_seed_update(), 1);
}

// Check that incrementing the boot attempts field fails when StoreImpl does not
// have permission to update the store file on disk.
TEST_F(StoreImplTest, IncrementBootAttempts_Failure_StoreWrongPermissions) {
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  ASSERT_NE(store_interface, nullptr);

  // Remove write permissions for store file.
  ASSERT_TRUE(
      SetPosixFilePermissions(store_path_, base::FILE_PERMISSION_READ_BY_USER));

  // Increment boot attempts.
  EXPECT_FALSE(store_interface->IncrementBootAttemptsSinceLastUpdate());
}

// Check correctness of clearing the boot attempts field in the store.
TEST_F(StoreImplTest, ClearBootAttempts_Success) {
  // Create store.
  Store store;
  store.set_boot_attempts_since_last_seed_update(1);

  ComputeHmac(store);

  // Serialize store.
  std::string serialized_store;
  ASSERT_TRUE(store.SerializeToString(&serialized_store));

  // Write serialized store to disk.
  ASSERT_TRUE(base::WriteFile(store_path_, serialized_store));

  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  ASSERT_NE(store_interface, nullptr);

  // Check boot attempts field.
  EXPECT_EQ(store_interface->GetBootAttemptsSinceLastUpdate(), 1);

  // Clear boot attempts.
  EXPECT_TRUE(store_interface->ClearBootAttemptsSinceLastUpdate());
  EXPECT_EQ(store_interface->GetBootAttemptsSinceLastUpdate(), 0);

  // Verify boot attempts update is reflected on disk.
  std::string store_content;
  ASSERT_TRUE(ReadFileToString(store_path_, &store_content));
  ASSERT_TRUE(store.ParseFromString(store_content));
  EXPECT_EQ(store.boot_attempts_since_last_seed_update(), 0);
}

// Check that clearing the boot attempts field fails when StoreImpl does not
// have permission to update the store file on disk.
TEST_F(StoreImplTest, ClearBootAttempts_Failure_StoreWrongPermissions) {
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  ASSERT_NE(store_interface, nullptr);

  // Remove write permissions for store file.
  ASSERT_TRUE(
      SetPosixFilePermissions(store_path_, base::FILE_PERMISSION_READ_BY_USER));

  // Clear boot attempts.
  EXPECT_FALSE(store_interface->ClearBootAttemptsSinceLastUpdate());
}

// Check correctness of updating the seed field in the store.
TEST_F(StoreImplTest, UpdateSeed_Success) {
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  ASSERT_NE(store_interface, nullptr);

  // Check seed field.
  SeedDetails seed;
  EXPECT_THAT(store_interface->GetLastGoodSeed(),
              EqualsProto(seed));  // Check for empty seed.

  // Update seed.
  seed.set_compressed_data("test_compressed_data");
  EXPECT_TRUE(store_interface->SetLastGoodSeed(seed));
  EXPECT_THAT(store_interface->GetLastGoodSeed(), EqualsProto(seed));

  // Verify seed update is reflected on disk.
  Store store;
  std::string store_content;
  ASSERT_TRUE(ReadFileToString(store_path_, &store_content));

  ASSERT_TRUE(store.ParseFromString(store_content));
  EXPECT_THAT(store.last_good_seed(), EqualsProto(seed));
}

// Check that updating the seed field fails when StoreImpl does not
// have permission to update the store file on disk.
TEST_F(StoreImplTest, UpdateSeed_Failure_StoreWrongPermissions) {
  std::unique_ptr<StoreInterface> store_interface =
      StoreImpl::Create(store_path_, tpm_seed_path_);
  ASSERT_NE(store_interface, nullptr);

  // Remove write permissions for store file.
  ASSERT_TRUE(
      SetPosixFilePermissions(store_path_, base::FILE_PERMISSION_READ_BY_USER));

  // Update seed.
  SeedDetails seed;
  seed.set_compressed_data("test_compressed_data");
  EXPECT_FALSE(store_interface->SetLastGoodSeed(seed));
}
}  // namespace featured
