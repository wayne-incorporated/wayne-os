// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/recursive_copy_progress.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {

class RecursiveCopyProgressTest : public testing::Test {
 public:
  RecursiveCopyProgressTest() {
    fake_samba_ = std::make_unique<FakeSambaInterface>();
  }
  RecursiveCopyProgressTest(const RecursiveCopyProgressTest&) = delete;
  RecursiveCopyProgressTest& operator=(const RecursiveCopyProgressTest&) =
      delete;

  ~RecursiveCopyProgressTest() override = default;

 protected:
  // Creates a share at smb://wdshare/test
  void PrepareFileSystem() {
    fake_samba_->AddDirectory(GetDefaultServer());
    fake_samba_->AddDirectory(GetDefaultMountRoot());
  }

  std::unique_ptr<FakeSambaInterface> fake_samba_;
};

TEST_F(RecursiveCopyProgressTest, CopyFailsWhenSourceDoesNotExist) {
  const std::string source_path = GetDefaultFullPath("non_existent_source_dir");
  const std::string target_path = GetDefaultFullPath("target");

  PrepareFileSystem();

  RecursiveCopyProgress recursive_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      recursive_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(ENOENT, error);
}

TEST_F(RecursiveCopyProgressTest, CopyFailsWhenTargetExists) {
  const std::string source_path = GetDefaultFullPath("source_dir");
  const std::string target_path = GetDefaultFullPath("target");

  PrepareFileSystem();
  fake_samba_->AddDirectory(source_path);
  fake_samba_->AddDirectory(target_path);

  RecursiveCopyProgress recursive_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      recursive_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(EEXIST, error);
}

TEST_F(RecursiveCopyProgressTest, RecursiveCopyFailsOnFile) {
  const std::string source_path = GetDefaultFullPath("source_dir");
  const std::string target_path = GetDefaultFullPath("target_dir");

  PrepareFileSystem();
  fake_samba_->AddFile(source_path);

  RecursiveCopyProgress recursive_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      recursive_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(ENOTDIR, error);
}

TEST_F(RecursiveCopyProgressTest, RecursiveCopySucceedsOnEmptyDirectory) {
  const std::string source_path = GetDefaultFullPath("source_dir");
  const std::string target_path = GetDefaultFullPath("target_dir");

  PrepareFileSystem();
  fake_samba_->AddDirectory(source_path);

  RecursiveCopyProgress recursive_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      recursive_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(0, error);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path));
}

TEST_F(RecursiveCopyProgressTest, RecursiveCopySucceedsOnNestedDirs) {
  const std::string source_path = GetDefaultFullPath("source_dir");
  const std::string source_path_2 = GetDefaultFullPath("source_dir/inner");

  const std::string target_path = GetDefaultFullPath("target_dir");
  const std::string target_path_2 = GetDefaultFullPath("target_dir/inner");

  PrepareFileSystem();
  fake_samba_->AddDirectory(source_path);
  fake_samba_->AddDirectory(source_path_2);

  RecursiveCopyProgress recursive_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      recursive_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_TRUE(should_continue_copy);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path));

  should_continue_copy = recursive_copy_progress.ContinueCopy(&error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(0, error);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path_2));
}

TEST_F(RecursiveCopyProgressTest, RecursiveCopySucceedsOnSingleFileInDir) {
  const std::string source_path = GetDefaultFullPath("source_dir");
  const std::string source_path_2 = GetDefaultFullPath("source_dir/inner");

  const std::string target_path = GetDefaultFullPath("target_dir");
  const std::string target_path_2 = GetDefaultFullPath("target_dir/inner");

  PrepareFileSystem();
  fake_samba_->AddDirectory(source_path);
  fake_samba_->AddFile(source_path_2);

  RecursiveCopyProgress recursive_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      recursive_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_TRUE(should_continue_copy);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path));

  should_continue_copy = recursive_copy_progress.ContinueCopy(&error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_EQ(0, error);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path_2));
}

TEST_F(RecursiveCopyProgressTest, RecursiveCopySucceedsWithFileData) {
  const std::string source_path = GetDefaultFullPath("source_dir");
  const std::string source_path_2 = GetDefaultFullPath("source_dir/inner");
  const std::string source_path_3 = GetDefaultFullPath("source_dir/file");
  const std::vector<uint8_t> source_3_data = {1, 2, 3, 4, 5};

  const std::string target_path = GetDefaultFullPath("target_dir");
  const std::string target_path_2 = GetDefaultFullPath("target_dir/inner");
  const std::string target_path_3 = GetDefaultFullPath("target_dir/file");

  PrepareFileSystem();
  fake_samba_->AddDirectory(source_path);
  fake_samba_->AddDirectory(source_path_2);
  fake_samba_->AddFile(source_path_3, 0 /* date */, source_3_data);

  RecursiveCopyProgress recursive_copy_progress(fake_samba_.get());

  int32_t error;
  bool should_continue_copy =
      recursive_copy_progress.StartCopy(source_path, target_path, &error);
  EXPECT_TRUE(should_continue_copy);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path));

  should_continue_copy = recursive_copy_progress.ContinueCopy(&error);
  EXPECT_TRUE(should_continue_copy);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path_2));

  should_continue_copy = recursive_copy_progress.ContinueCopy(&error);
  EXPECT_FALSE(should_continue_copy);
  EXPECT_TRUE(fake_samba_->EntryExists(target_path_3));
  EXPECT_TRUE(fake_samba_->IsFileDataEqual(target_path_3, source_3_data));
}

}  // namespace smbprovider
