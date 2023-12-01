// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/iterator/depth_first_iterator.h"
#include "smbprovider/smbprovider_helper.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {

// Derived version of DepthFirstIterator. Since this class does not override
// niether OnPush nor OnPop, it performs an Inorder traversal of files only.
class TestDepthFirstIterator : public DepthFirstIterator {
 public:
  TestDepthFirstIterator(const std::string& dir_path,
                         SambaInterface* samba_interface)
      : DepthFirstIterator(dir_path, samba_interface) {}
  TestDepthFirstIterator(const TestDepthFirstIterator&) = delete;
  TestDepthFirstIterator& operator=(const TestDepthFirstIterator&) = delete;
};

class DepthFirstIteratorTest : public testing::Test {
 public:
  DepthFirstIteratorTest() {}
  DepthFirstIteratorTest(const DepthFirstIteratorTest&) = delete;
  DepthFirstIteratorTest& operator=(const DepthFirstIteratorTest&) = delete;

  ~DepthFirstIteratorTest() override = default;

 protected:
  void CreateDefaultMountRoot() {
    fake_samba_.AddDirectory(GetDefaultServer());
    fake_samba_.AddDirectory(GetDefaultMountRoot());
  }

  FakeSambaInterface fake_samba_;
};

// DepthFirstIterator fails to initialize on a non-existent directory.
TEST_F(DepthFirstIteratorTest, InitFailsOnNonExistentDir) {
  TestDepthFirstIterator it("smb://non-existent-path/", &fake_samba_);

  EXPECT_EQ(ENOENT, it.Init());
}

// DepthFirstIterator fails to initialize on a file.
TEST_F(DepthFirstIteratorTest, InitFailsOnFile) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddFile(GetAddedFullFilePath());

  TestDepthFirstIterator it(GetAddedFullFilePath(), &fake_samba_);

  EXPECT_EQ(ENOTDIR, it.Init());
}

// DepthFirstIterator fails to initialize on a non-file, non-directory.
TEST_F(DepthFirstIteratorTest, InitFailsOnNonFileNonDirectory) {
  CreateDefaultMountRoot();
  const std::string printer_path = "/path/canon.cn";

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddEntry(GetDefaultFullPath(printer_path), SMBC_PRINTER_SHARE);

  TestDepthFirstIterator it(GetDefaultFullPath(printer_path), &fake_samba_);

  EXPECT_EQ(ENOTDIR, it.Init());
}

// DepthFirstIterator initializes successfully and sets is_done on a directory
// with nothing in it.
TEST_F(DepthFirstIteratorTest, InitSucceedsAndSetsDoneOnCompletelyEmptyDir) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetDefaultFullPath("/path"));

  TestDepthFirstIterator it(GetDefaultFullPath("/path"), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_TRUE(it.IsDone());
}

// DepthFirstIterator initializes successfully and sets is_done on a directory
// with only empty nested directories and no files.
TEST_F(DepthFirstIteratorTest, InitSucceedsAndSetsDoneOnDirOfEmptyDirs) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetDefaultFullPath("/path"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/dogs"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/cats"));

  TestDepthFirstIterator it(GetDefaultFullPath("/path"), &fake_samba_);

  // Should be done iterating since there are no files.
  EXPECT_EQ(0, it.Init());
  EXPECT_TRUE(it.IsDone());
}

// DepthFirstIterator initializies successfully and sets is_done on a directory
// with nested directories with their own nested directories, but no files.
TEST_F(DepthFirstIteratorTest, InitSucceedsAndSetsDoneOnDirOfDirOfEmtpyDir) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetDefaultFullPath("/path"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/dogs"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/dogs/lab"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/dogs/golden"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/cats"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/cats/shorthair"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/cats/persian"));

  TestDepthFirstIterator it(GetDefaultFullPath("/path"), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_TRUE(it.IsDone());
}

// DepthFirstIterator initializes correctly on a directory with one file.
TEST_F(DepthFirstIteratorTest, InitSucceedsOnOneFile) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetDefaultFullPath("/path"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/dog.jpg"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/cats"));

  TestDepthFirstIterator it(GetDefaultFullPath("/path"), &fake_samba_);

  EXPECT_EQ(0, it.Init());

  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("dog.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);
  EXPECT_EQ(0, it.Next());

  EXPECT_TRUE(it.IsDone());
}

// DepthFirstIterator initializes correctly and iterates over a directory with
// an entry and another directory with an entry.
TEST_F(DepthFirstIteratorTest, NextSucceedsOnSimpleMultiLevelFileSystem) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetDefaultFullPath("/path"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/dog.jpg"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/cats"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/cats/kitty.jpg"));

  TestDepthFirstIterator it(GetDefaultFullPath("/path"), &fake_samba_);

  EXPECT_EQ(0, it.Init());

  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("dog.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);
  EXPECT_EQ(0, it.Next());

  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("kitty.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);
  EXPECT_EQ(0, it.Next());

  EXPECT_TRUE(it.IsDone());
}

// DepthFirstIterator iterates over files in muli-level filesystem correctly.
TEST_F(DepthFirstIteratorTest, NextSucceedsOnComplexMultiLevelFileSystem) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetDefaultFullPath("/path"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/1.jpg"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/dogs"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/dogs/2.jpg"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/dogs/mouse"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/dogs/3.jpg"));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/cats"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/cats/4.jpg"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/cats/5.jpg"));

  TestDepthFirstIterator it(GetDefaultFullPath("/path"), &fake_samba_);

  EXPECT_EQ(0, it.Init());

  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("1.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);
  EXPECT_EQ(0, it.Next());

  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("2.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);
  EXPECT_EQ(0, it.Next());

  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("3.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);
  EXPECT_EQ(0, it.Next());

  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("4.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);
  EXPECT_EQ(0, it.Next());

  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("5.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);
  EXPECT_EQ(0, it.Next());

  EXPECT_TRUE(it.IsDone());
}

}  // namespace smbprovider
