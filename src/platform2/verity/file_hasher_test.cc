// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by the GPL v2 license that can
// be found in the LICENSE file.
//
// Tests for verity::FileHasher

#include <utility>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "verity/file_hasher.h"

namespace verity {

namespace {
// Just 32 byte salt. (There is no meaning to this pattern.)
constexpr char kSalt[] =
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
}  // namespace

class FileHasherTest : public ::testing::Test {
 public:
  FileHasherTest() {}
  virtual ~FileHasherTest() = default;
  void SetUp() {
    EXPECT_TRUE(temp_dir_.CreateUniqueTempDir());
    target_file_.reset(new base::File(
        temp_dir_.GetPath().Append("target_file.bin"),
        base::File::FLAG_CREATE_ALWAYS | base::File::FLAG_WRITE));
    EXPECT_TRUE(target_file_->IsValid());

    auto test_data_path = base::FilePath(getenv("SRC")).Append("test_data");
    small_file_.reset(
        new base::File(test_data_path.Append("small_file.bin"),
                       base::File::FLAG_OPEN | base::File::FLAG_READ));
    EXPECT_TRUE(small_file_->IsValid());
  }

 protected:
  base::ScopedTempDir temp_dir_;

  // This file is created by the following command:
  // `dd if=/dev/urandom of=small_file.bin count=2 bs=4096`
  std::unique_ptr<base::File> small_file_;
  std::unique_ptr<base::File> target_file_;
};

TEST_F(FileHasherTest, EndToEnd) {
  verity::FileHasher hasher(std::move(small_file_), std::move(target_file_), 0,
                            kSha256HashName);
  EXPECT_TRUE(hasher.Initialize());
  hasher.set_salt(reinterpret_cast<const char*>(kSalt));
  EXPECT_TRUE(hasher.Hash());
  EXPECT_TRUE(hasher.Store());

  hasher.PrintTable(true);
  EXPECT_EQ(hasher.GetTable(true),
            "0 16 verity payload=ROOT_DEV hashtree=HASH_DEV hashstart=16 "
            "alg=sha256 root_hexdigest=21f0268f4a293d8110074c678a651c638d"
            "56a610dd2662975a35d451d3258018 salt=abcdef0123456789abcdef01"
            "23456789abcdef0123456789abcdef0123456789");
}

TEST_F(FileHasherTest, BadSourceFile) {
  verity::FileHasher hasher(nullptr, std::move(target_file_), 0,
                            kSha256HashName);
  EXPECT_FALSE(hasher.Initialize());
}

TEST_F(FileHasherTest, BadTargetFile) {
  verity::FileHasher hasher(std::move(small_file_), nullptr, 0,
                            kSha256HashName);
  EXPECT_FALSE(hasher.Initialize());
}

TEST_F(FileHasherTest, BadAlgorithmName) {
  verity::FileHasher hasher(std::move(small_file_), std::move(target_file_), 0,
                            "foo");
  EXPECT_FALSE(hasher.Initialize());
}

TEST_F(FileHasherTest, BadBlockSize) {
  // The source file size is just 2 4KiB blocks.
  verity::FileHasher hasher(std::move(small_file_), std::move(target_file_), 3,
                            kSha256HashName);
  EXPECT_FALSE(hasher.Initialize());
}

}  // namespace verity
