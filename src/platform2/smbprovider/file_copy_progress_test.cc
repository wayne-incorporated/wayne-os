// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/file_copy_progress.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {

class FileCopyProgressTest : public testing::Test {
 public:
  FileCopyProgressTest()
      : fake_samba_(std::make_unique<FakeSambaInterface>()) {}
  FileCopyProgressTest(const FileCopyProgressTest&) = delete;
  FileCopyProgressTest& operator=(const FileCopyProgressTest&) = delete;

  ~FileCopyProgressTest() override = default;

 protected:
  // Creates a share at smb://wdshare/test
  void PrepareFileSystem() {
    fake_samba_->AddDirectory(GetDefaultServer());
    fake_samba_->AddDirectory(GetDefaultMountRoot());
  }

  std::unique_ptr<FakeSambaInterface> fake_samba_;
};

// The copy fails if the source does not exist.
TEST_F(FileCopyProgressTest, CopyFailsWhenSourceDoesNotExist) {
  const std::string source_path = GetDefaultFullPath("non_existent_source");
  const std::string target_path = GetDefaultFullPath("target");

  PrepareFileSystem();

  FileCopyProgress file_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      file_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(ENOENT, error);
}

// The copy fails if the target already exists.
TEST_F(FileCopyProgressTest, CopyFailsWhenTargetExists) {
  const std::string source_path = GetDefaultFullPath("source");
  const std::string target_path = GetDefaultFullPath("target");

  PrepareFileSystem();
  fake_samba_->AddFile(source_path);
  fake_samba_->AddFile(target_path);

  FileCopyProgress file_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      file_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(EEXIST, error);
}

// Copy succeeds on an empty file.
TEST_F(FileCopyProgressTest, CopySucceedsOnEmptyFile) {
  const std::string source_path = GetDefaultFullPath("source");
  const std::string target_path = GetDefaultFullPath("target");

  PrepareFileSystem();
  fake_samba_->AddFile(source_path);

  FileCopyProgress file_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      file_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(0, error);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path));
}

// Copy succeeds with chunk size = size of file.
TEST_F(FileCopyProgressTest, CopySucceedsChunkEqualToFile) {
  const std::string source_path = GetDefaultFullPath("source");
  const std::string target_path = GetDefaultFullPath("target");
  const std::vector<uint8_t> source_data = {1, 2, 3, 4, 5};

  PrepareFileSystem();
  fake_samba_->AddFile(source_path, 0 /* date */, source_data);

  const off_t iteration_chunk_size = source_data.size();
  FileCopyProgress file_copy_progress(fake_samba_.get(), iteration_chunk_size);

  int32_t error;
  bool should_continue_copy =
      file_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(0, error);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path));
  EXPECT_TRUE(fake_samba_->IsFileDataEqual(target_path, source_data));
}

// Copy succeeds with chunk size > size of file.
TEST_F(FileCopyProgressTest, CopySucceedsChunkBiggerThanFile) {
  const std::string source_path = GetDefaultFullPath("source");
  const std::string target_path = GetDefaultFullPath("target");
  const std::vector<uint8_t> source_data = {1, 2, 3, 4, 5};

  PrepareFileSystem();
  fake_samba_->AddFile(source_path, 0 /* date */, source_data);

  const off_t iteration_chunk_size = source_data.size() + 1;
  FileCopyProgress file_copy_progress(fake_samba_.get(), iteration_chunk_size);

  int32_t error;
  bool should_continue_copy =
      file_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(0, error);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path));
  EXPECT_TRUE(fake_samba_->IsFileDataEqual(target_path, source_data));
}

// Copy suceeds using continue.
TEST_F(FileCopyProgressTest, CopySucceedsWithContinue) {
  const std::string source_path = GetDefaultFullPath("source");
  const std::string target_path = GetDefaultFullPath("target");
  const std::vector<uint8_t> source_data = {1, 2, 3, 4, 5};

  PrepareFileSystem();
  fake_samba_->AddFile(source_path, 0 /* date */, source_data);

  const off_t iteration_chunk_size = source_data.size() - 1;
  FileCopyProgress file_copy_progress(fake_samba_.get(), iteration_chunk_size);

  int32_t error;
  bool should_continue_copy =
      file_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_TRUE(should_continue_copy);

  should_continue_copy = file_copy_progress.ContinueCopy(&error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(0, error);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path));
  EXPECT_TRUE(fake_samba_->IsFileDataEqual(target_path, source_data));
}

}  // namespace smbprovider
