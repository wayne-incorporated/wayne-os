// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/login_screen_storage.h"

#include <algorithm>
#include <memory>
#include <tuple>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/errors/error.h>
#include <gtest/gtest.h>

#include "login_manager/fake_secret_util.h"
#include "login_manager/login_screen_storage/login_screen_storage_index.pb.h"
#include "login_manager/secret_util.h"

namespace login_manager {

namespace {

constexpr char kLoginScreenStoragePath[] = "login_screen_storage";
constexpr char kTestKey[] = "testkey";

LoginScreenStorageMetadata MakeMetadata(bool clear_on_session_exit) {
  LoginScreenStorageMetadata metadata;
  metadata.set_clear_on_session_exit(clear_on_session_exit);
  return metadata;
}

// Checks that two given lists of login screen storage keys are equal.
bool KeyListsAreEqual(std::vector<std::string> lhs,
                      std::vector<std::string> rhs) {
  sort(lhs.begin(), lhs.end());
  sort(rhs.begin(), rhs.end());
  return lhs == rhs;
}

// Checks that a given instace of |LoginScreenStorageIndex| has a set of keys
// equal to |expected_keys|.
bool IndexKeysEqualTo(const LoginScreenStorageIndex& index,
                      std::vector<std::string> expected_keys) {
  auto keys = index.keys();
  std::vector<std::string> keys_vec(keys.begin(), keys.end());
  return KeyListsAreEqual(std::move(keys_vec), std::move(expected_keys));
}

// Generating a test value with a maximal supported length.
std::vector<uint8_t> GenerateLongTestValue() {
  return std::vector<uint8_t>(secret_util::kSharedMemorySecretSizeLimit, 0xb1);
}

}  // namespace

class LoginScreenStorageTestBase : public ::testing::Test {
 public:
  void SetUp() override {
    ASSERT_TRUE(tmpdir_.CreateUniqueTempDir());
    storage_path_ = tmpdir_.GetPath().Append(kLoginScreenStoragePath);
    auto shared_memory_util =
        std::make_unique<secret_util::FakeSharedMemoryUtil>();
    shared_memory_util_ = shared_memory_util.get();
    storage_ = std::make_unique<LoginScreenStorage>(
        storage_path_, std::move(shared_memory_util));
  }

 protected:
  base::FilePath GetKeyPath(const std::string& key) const {
    return base::FilePath(storage_path_)
        .Append(secret_util::StringToSafeFilename(key));
  }

  base::FilePath GetIndexPath() const {
    return base::FilePath(storage_path_)
        .Append(kLoginScreenStorageIndexFilename);
  }

  LoginScreenStorageIndex LoadIndex() const {
    const base::FilePath index_path = GetIndexPath();
    EXPECT_TRUE(base::PathExists(index_path));

    std::string index_blob;
    LoginScreenStorageIndex index;
    if (base::ReadFileToString(index_path, &index_blob))
      index.ParseFromString(index_blob);
    return index;
  }

  base::ScopedFD MakeValueFD(const std::vector<uint8_t>& value) {
    return shared_memory_util_->WriteDataToSharedMemory(value);
  }

  base::ScopedTempDir tmpdir_;
  base::FilePath storage_path_;
  secret_util::SharedMemoryUtil* shared_memory_util_;
  std::unique_ptr<LoginScreenStorage> storage_;
};

class LoginScreenStorageTest
    : public LoginScreenStorageTestBase,
      public testing::WithParamInterface<
          std::tuple<LoginScreenStorageMetadata,
                     std::vector<uint8_t> /* test_key */>> {
 protected:
  const LoginScreenStorageMetadata metadata_param_ = std::get<0>(GetParam());
  const std::vector<uint8_t> value_param_ = std::get<1>(GetParam());
};

TEST_P(LoginScreenStorageTest, StoreRetrieve) {
  base::ScopedFD value_fd = MakeValueFD(value_param_);

  brillo::ErrorPtr error;
  storage_->Store(&error, kTestKey, metadata_param_, value_param_.size(),
                  value_fd);
  EXPECT_FALSE(error.get());

  base::ScopedFD out_value_fd;
  uint64_t out_value_size;
  storage_->Retrieve(&error, kTestKey, &out_value_size, &out_value_fd);
  EXPECT_FALSE(error.get());
  EXPECT_EQ(value_param_.size(), out_value_size);

  std::vector<uint8_t> out_value;
  EXPECT_TRUE(shared_memory_util_->ReadDataFromSharedMemory(
      out_value_fd, out_value_size, &out_value));
  EXPECT_EQ(value_param_, out_value);

  // Writing a different value to make sure it will replace the old one.
  const std::vector<uint8_t> kDifferentValue{0x1a, 0x1b};
  base::ScopedFD different_value_fd = MakeValueFD(kDifferentValue);
  storage_->Store(&error, kTestKey, metadata_param_, kDifferentValue.size(),
                  different_value_fd);
  EXPECT_FALSE(error.get());

  storage_->Retrieve(&error, kTestKey, &out_value_size, &out_value_fd);
  EXPECT_FALSE(error.get());
  EXPECT_EQ(kDifferentValue.size(), out_value_size);

  EXPECT_TRUE(shared_memory_util_->ReadDataFromSharedMemory(
      out_value_fd, out_value_size, &out_value));
  EXPECT_EQ(kDifferentValue, out_value);
}

TEST_P(LoginScreenStorageTest, CannotRetrieveDeletedKey) {
  base::ScopedFD value_fd = MakeValueFD(value_param_);

  brillo::ErrorPtr error;
  storage_->Store(&error, kTestKey, metadata_param_, value_param_.size(),
                  value_fd);
  EXPECT_FALSE(error.get());

  storage_->Delete(kTestKey);

  base::ScopedFD out_value_fd;
  uint64_t value_size;
  storage_->Retrieve(&error, kTestKey, &value_size, &out_value_fd);
  EXPECT_TRUE(error.get());
}

INSTANTIATE_TEST_SUITE_P(
    LoginScreenStorageTest,
    LoginScreenStorageTest,
    testing::Combine(
        testing::Values(MakeMetadata(/*clear_on_session_exit=*/false),
                        MakeMetadata(/*clear_on_session_exit=*/true)),
        testing::Values(std::vector<uint8_t>{0xb1, 0x0b},
                        GenerateLongTestValue())));

TEST_F(LoginScreenStorageTestBase, RetrieveInvalidData) {
  const base::FilePath path = GetKeyPath(kTestKey);

  // Make the storage subdirectory
  EXPECT_TRUE(base::CreateDirectory(path.DirName()));

  // Create an empty file
  base::ScopedFILE file(base::OpenFile(GetKeyPath(kTestKey), "w"));
  EXPECT_NE(file, nullptr);
  file.reset();

  brillo::ErrorPtr error;
  base::ScopedFD out_value_fd;
  uint64_t value_size;
  // CreateSharedMemoryWithData should fail because it can't create
  // zero-sized shared memory, check that Retrieve propagates that
  // failure.
  EXPECT_FALSE(
      storage_->Retrieve(&error, kTestKey, &value_size, &out_value_fd));
}

class LoginScreenStorageTestPersistent : public LoginScreenStorageTestBase {
 protected:
  const std::vector<uint8_t> test_value_{0xb1, 0x0b};
};

TEST_F(LoginScreenStorageTestPersistent, StoreOverridesPersistentKey) {
  brillo::ErrorPtr error;
  {
    base::ScopedFD value_fd = MakeValueFD(test_value_);
    EXPECT_TRUE(base::CreateDirectory(storage_path_));
    storage_->Store(&error, kTestKey,
                    MakeMetadata(/*clear_on_session_exit=*/false),
                    test_value_.size(), value_fd);
    EXPECT_FALSE(error.get());
  }

  const base::FilePath key_path = GetKeyPath(kTestKey);
  EXPECT_TRUE(base::PathExists(key_path));

  {
    base::ScopedFD value_fd = MakeValueFD(test_value_);
    storage_->Store(&error, kTestKey,
                    MakeMetadata(/*clear_on_session_exit=*/true),
                    test_value_.size(), value_fd);
    EXPECT_FALSE(error.get());
  }

  EXPECT_FALSE(base::PathExists(key_path));
}

TEST_F(LoginScreenStorageTestPersistent, StoreCreatesDirectoryIfNotExistant) {
  base::DeletePathRecursively(storage_path_);

  base::ScopedFD value_fd = MakeValueFD(test_value_);
  brillo::ErrorPtr error;
  storage_->Store(&error, kTestKey,
                  MakeMetadata(/*clear_on_session_exit=*/false),
                  test_value_.size(), value_fd);
  EXPECT_FALSE(error.get());

  EXPECT_TRUE(base::DirectoryExists(storage_path_));
  EXPECT_TRUE(base::PathExists(GetKeyPath(kTestKey)));
}

TEST_F(LoginScreenStorageTestPersistent, OnlyStoredKeysAreListedInIndex) {
  const std::string kDifferentTestKey = "different_test_key";
  base::DeletePathRecursively(storage_path_);
  brillo::ErrorPtr error;

  {
    base::ScopedFD value_fd = MakeValueFD(test_value_);
    storage_->Store(&error, kTestKey,
                    MakeMetadata(/*clear_on_session_exit=*/false),
                    test_value_.size(), value_fd);
    EXPECT_FALSE(error.get());
    EXPECT_TRUE(KeyListsAreEqual(storage_->ListKeys(), {kTestKey}));
    EXPECT_TRUE(IndexKeysEqualTo(LoadIndex(), {kTestKey}));
  }

  // Index contains both keys after adding a diffrent key/value pair.
  {
    base::ScopedFD value_fd = MakeValueFD(test_value_);
    storage_->Store(&error, kDifferentTestKey,
                    MakeMetadata(/*clear_on_session_exit=*/false),
                    test_value_.size(), value_fd);
    EXPECT_FALSE(error.get());
    EXPECT_TRUE(
        KeyListsAreEqual(storage_->ListKeys(), {kTestKey, kDifferentTestKey}));
    EXPECT_TRUE(IndexKeysEqualTo(LoadIndex(), {kTestKey, kDifferentTestKey}));
  }

  // Index doesn't contain a key after overwriting it with an in-memory value,
  // but index still contains other keys.
  {
    base::ScopedFD value_fd = MakeValueFD(test_value_);
    storage_->Store(&error, kTestKey,
                    MakeMetadata(/*clear_on_session_exit=*/true),
                    test_value_.size(), value_fd);
    EXPECT_FALSE(error.get());
    // |kTestKey| should still be listed as a key, but shouldn't be present in
    // index.
    EXPECT_TRUE(
        KeyListsAreEqual(storage_->ListKeys(), {kTestKey, kDifferentTestKey}));
    EXPECT_TRUE(IndexKeysEqualTo(LoadIndex(), {kDifferentTestKey}));
  }

  // Index doesn't contain a key after deleting it.
  {
    storage_->Delete(kDifferentTestKey);
    EXPECT_TRUE(KeyListsAreEqual(storage_->ListKeys(), {kTestKey}));
    EXPECT_TRUE(IndexKeysEqualTo(LoadIndex(), {}));
  }
}

}  // namespace login_manager
