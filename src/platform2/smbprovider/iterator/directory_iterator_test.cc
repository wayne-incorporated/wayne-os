// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <gtest/gtest.h>

#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/fake_samba_proxy.h"
#include "smbprovider/iterator/directory_iterator.h"
#include "smbprovider/smbprovider_helper.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {

class DirectoryIteratorTest : public testing::Test {
 public:
  DirectoryIteratorTest() {}
  DirectoryIteratorTest(const DirectoryIteratorTest&) = delete;
  DirectoryIteratorTest& operator=(const DirectoryIteratorTest&) = delete;

 protected:
  void CreateDefaultMountRoot() {
    fake_samba_.AddDirectory(GetDefaultServer());
    fake_samba_.AddDirectory(GetDefaultMountRoot());
  }

  FakeSambaInterface fake_samba_;
};

// DirectoryIterator fails to initialize on a non-existent directory.
TEST_F(DirectoryIteratorTest, InitFailsOnNonExistentDir) {
  DirectoryIterator it("smb://non-existent-path/", &fake_samba_);

  EXPECT_EQ(ENOENT, it.Init());
}

// DirectoryIterator fails to initialize on a non-existent directory.
TEST_F(DirectoryIteratorTest, InitFailsOnNonExistentDirWithMetadata) {
  DirectoryIterator it("smb://non-existent-path/", &fake_samba_,
                       1 /* batch_size */, true /* include_metadata */);

  EXPECT_EQ(ENOENT, it.Init());
}

// DirectoryIterator fails to initialize on a file.
TEST_F(DirectoryIteratorTest, InitFailsOnFile) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddFile(GetAddedFullFilePath());

  DirectoryIterator it(GetAddedFullFilePath(), &fake_samba_);

  EXPECT_EQ(ENOTDIR, it.Init());
}

// DirectoryIterator fails to initialize on a non-file, non-directory.
TEST_F(DirectoryIteratorTest, InitFailsOnNonFileNonDirectory) {
  CreateDefaultMountRoot();
  const std::string printer_path = "/path/canon.cn";

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddEntry(GetDefaultFullPath(printer_path), SMBC_PRINTER_SHARE);

  DirectoryIterator it(GetDefaultFullPath(printer_path), &fake_samba_);

  EXPECT_EQ(ENOTDIR, it.Init());
}

// DirectoryIterator succeeds and sets is_done on an empty directory.
TEST_F(DirectoryIteratorTest, InitSucceedsAndSetsDoneOnEmptyDirectory) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_TRUE(it.IsDone());
}

// DirectoryIterator's destructor closes the underlying directory.
TEST_F(DirectoryIteratorTest, DestructorClosesDirectory) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());

  {
    DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_);
    EXPECT_EQ(0, it.Init());
    EXPECT_TRUE(it.IsDone());
    EXPECT_TRUE(fake_samba_.HasOpenEntries());
  }

  EXPECT_FALSE(fake_samba_.HasOpenEntries());
}

// DirectoryIterator's destructor can run after the Samba is deleted.
TEST_F(DirectoryIteratorTest, DestructorCanRunAfterSambaIsDeleted) {
  CreateDefaultMountRoot();
  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());

  std::unique_ptr<SambaInterface> proxy =
      std::make_unique<FakeSambaProxy>(&fake_samba_);

  {
    DirectoryIterator it(GetAddedFullDirectoryPath(), proxy.get());
    EXPECT_EQ(0, it.Init());
    EXPECT_TRUE(it.IsDone());
    EXPECT_TRUE(fake_samba_.HasOpenEntries());
    proxy.reset();
  }

  EXPECT_TRUE(fake_samba_.HasOpenEntries());
}

// DirectoryIterator succeeds and sets is_done on an empty directory.
TEST_F(DirectoryIteratorTest,
       InitSucceedsAndSetsDoneOnEmptyDirectoryWithMetadata) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_,
                       1 /* batch_size */, true /* include_metadata */);

  EXPECT_EQ(0, it.Init());
  EXPECT_TRUE(it.IsDone());
}

TEST_F(DirectoryIteratorTest, InitSucceedsAndSetsDoneOnSelfAndParentEntries) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/."));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/.."));

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_TRUE(it.IsDone());
}

// DirectoryIterator initializes correctly on a directory with one entry.
TEST_F(DirectoryIteratorTest, InitSucceedsOnNonEmptyDirectory) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddFile(GetAddedFullFilePath());

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());

  EXPECT_EQ("dog.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);

  EXPECT_EQ(0, it.Next());
  EXPECT_TRUE(it.IsDone());
}

// DirectoryIterator initializes correctly on a directory with one entry.
TEST_F(DirectoryIteratorTest, InitSucceedsOnNonEmptyDirectoryWithMetadata) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());

  const uint64_t expected_size = 99;
  const time_t expected_date = 888822222;
  fake_samba_.AddFile(GetAddedFullFilePath(), expected_size, expected_date);

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_,
                       1 /* batch_size */, true /* include_metadata */);
  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());

  EXPECT_EQ("dog.jpg", it.Get().name);
  EXPECT_FALSE(it.Get().is_directory);
  EXPECT_EQ(expected_size, it.Get().size);
  EXPECT_EQ(expected_date, it.Get().last_modified_time);

  EXPECT_EQ(0, it.Next());
  EXPECT_TRUE(it.IsDone());
}

// DirectoryIterator correctly initializes and calls next on 1 entry.
TEST_F(DirectoryIteratorTest, NextSucceedsAndSetsDoneOnOneEntry) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddFile(GetAddedFullFilePath());
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/cats"));

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("dog.jpg", it.Get().name);

  EXPECT_EQ(0, it.Next());
  EXPECT_EQ("cats", it.Get().name);
  EXPECT_FALSE(it.IsDone());

  EXPECT_EQ(0, it.Next());
  EXPECT_TRUE(it.IsDone());
}

// DirectoryIterator iterates correctly over a directory with multiple entries
// and a large buffer.
TEST_F(DirectoryIteratorTest, NextReturnsMultipleEntries) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddFile(GetAddedFullFilePath());
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/cats"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/dogs2.jpg"));

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("dog.jpg", it.Get().name);

  EXPECT_EQ(0, it.Next());
  EXPECT_EQ("cats", it.Get().name);
  EXPECT_FALSE(it.IsDone());

  EXPECT_EQ(0, it.Next());
  EXPECT_EQ("dogs2.jpg", it.Get().name);
  EXPECT_FALSE(it.IsDone());

  EXPECT_EQ(0, it.Next());
  EXPECT_TRUE(it.IsDone());
}

// DirectoryIterator does not iterate over '.' and '..' directory entries.
TEST_F(DirectoryIteratorTest, DirItOmitsSelfAndParentEntries) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddFile(GetAddedFullFilePath());
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/."));
  fake_samba_.AddDirectory(GetDefaultFullPath("/path/.."));

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("dog.jpg", it.Get().name);

  EXPECT_EQ(0, it.Next());
  EXPECT_TRUE(it.IsDone());
}

// DirectoryIterator does not iterate over entries containing '/' or '\'
// in the name.
TEST_F(DirectoryIteratorTest, DirItOmitsRelativeEntries) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddFile(GetAddedFullFilePath());
  fake_samba_.AddFile(GetAddedFullDirectoryPath(), "foo/bar");
  fake_samba_.AddFile(GetAddedFullDirectoryPath(), "bar\\foo");

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_);

  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("dog.jpg", it.Get().name);

  EXPECT_EQ(0, it.Next());
  EXPECT_TRUE(it.IsDone());
}

// DirectoryIterator succeeds with multiple entries when the batch size is
// large enough for just one entry at a time.
TEST_F(DirectoryIteratorTest, DirItSucceedsWithMultipleUsesOfSmallBatch) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddFile(GetDefaultFullPath("/path/file1.jpg"));
  fake_samba_.AddFile(GetDefaultFullPath("/path/file2.jpg"));

  DirectoryIterator it(GetAddedFullDirectoryPath(), &fake_samba_, 1);

  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());
  EXPECT_EQ("file1.jpg", it.Get().name);

  EXPECT_EQ(0, it.Next());
  EXPECT_EQ("file2.jpg", it.Get().name);
  EXPECT_FALSE(it.IsDone());

  EXPECT_EQ(0, it.Next());
  EXPECT_TRUE(it.IsDone());
}

}  // namespace smbprovider
