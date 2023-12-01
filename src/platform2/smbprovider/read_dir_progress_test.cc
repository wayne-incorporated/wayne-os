// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/test/simple_test_tick_clock.h>
#include <gtest/gtest.h>

#include "smbprovider/constants.h"
#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/iterator/caching_iterator.h"
#include "smbprovider/metadata_cache.h"
#include "smbprovider/read_dir_progress.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {

class ReadDirProgressTest : public testing::Test {
 public:
  ReadDirProgressTest()
      : fake_samba_(std::make_unique<FakeSambaInterface>()),
        fake_tick_clock_(std::make_unique<base::SimpleTestTickClock>()) {
    cache_ = std::make_unique<MetadataCache>(
        fake_tick_clock_.get(),
        base::Microseconds(kMetadataCacheLifetimeMicroseconds),
        MetadataCache::Mode::kDisabled);
  }
  ReadDirProgressTest(const ReadDirProgressTest&) = delete;
  ReadDirProgressTest& operator=(const ReadDirProgressTest&) = delete;

  ~ReadDirProgressTest() override = default;

 protected:
  void PrepareFileSystem() {
    fake_samba_->AddDirectory(GetDefaultServer());
    fake_samba_->AddDirectory(GetDefaultMountRoot());
  }

  std::unique_ptr<FakeSambaInterface> fake_samba_;
  std::unique_ptr<base::TickClock> fake_tick_clock_;
  std::unique_ptr<MetadataCache> cache_;
};

TEST_F(ReadDirProgressTest, StartSucceedsOnEmptyDir) {
  const std::string empty_dir = GetDefaultFullPath("dir");

  PrepareFileSystem();
  fake_samba_->AddDirectory(empty_dir);

  ReadDirProgress read_dir_progress(fake_samba_.get());

  int32_t error;
  DirectoryEntryListProto entries;
  bool should_continue_read_dir =
      read_dir_progress.StartReadDir(empty_dir, cache_.get(), &error, &entries);

  EXPECT_FALSE(should_continue_read_dir);
  EXPECT_EQ(0, error);
  EXPECT_EQ(0, entries.entries_size());
}

TEST_F(ReadDirProgressTest, StartSucceedsOnNonEmptyDir) {
  const std::string dir_path = GetDefaultFullPath("dir");
  const std::string file_name = "file1.txt";
  const std::string file_path = dir_path + "/" + file_name;

  PrepareFileSystem();
  fake_samba_->AddDirectory(dir_path);
  fake_samba_->AddFile(file_path);

  ReadDirProgress read_dir_progress(fake_samba_.get());

  int32_t error;
  DirectoryEntryListProto entries;
  bool should_continue_read_dir =
      read_dir_progress.StartReadDir(dir_path, cache_.get(), &error, &entries);

  EXPECT_FALSE(should_continue_read_dir);
  EXPECT_EQ(0, error);

  EXPECT_EQ(1, entries.entries_size());
  EXPECT_EQ(file_name, entries.entries(0).name());
}

TEST_F(ReadDirProgressTest, StartFailsWhenDirectoryDoesNotExist) {
  const std::string dir_path = GetDefaultFullPath("dir");

  ReadDirProgress read_dir_progress(fake_samba_.get());

  int32_t error;
  DirectoryEntryListProto entries;
  bool should_continue_read_dir =
      read_dir_progress.StartReadDir(dir_path, cache_.get(), &error, &entries);

  EXPECT_FALSE(should_continue_read_dir);
  EXPECT_EQ(ENOENT, error);
}

TEST_F(ReadDirProgressTest, StartAndContinue) {
  const std::string dir_path = GetDefaultFullPath("dir");
  const std::string file_name_1 = "file1.txt";
  const std::string file_path_1 = dir_path + "/" + file_name_1;
  const std::string file_name_2 = "file2.txt";
  const std::string file_path_2 = dir_path + "/" + file_name_2;

  PrepareFileSystem();
  fake_samba_->AddDirectory(dir_path);
  fake_samba_->AddFile(file_path_1);
  fake_samba_->AddFile(file_path_2);

  ReadDirProgress read_dir_progress(fake_samba_.get(),
                                    1 /* initial_batch_size*/);

  int32_t error;
  DirectoryEntryListProto entries;
  bool should_continue_read_dir =
      read_dir_progress.StartReadDir(dir_path, cache_.get(), &error, &entries);

  EXPECT_TRUE(should_continue_read_dir);
  EXPECT_EQ(0, error);

  EXPECT_EQ(1, entries.entries_size());
  EXPECT_EQ(file_name_1, entries.entries(0).name());

  should_continue_read_dir =
      read_dir_progress.ContinueReadDir(&error, &entries);

  EXPECT_FALSE(should_continue_read_dir);
  EXPECT_EQ(0, error);

  EXPECT_EQ(1, entries.entries_size());
  EXPECT_EQ(file_name_2, entries.entries(0).name());
}

TEST_F(ReadDirProgressTest, BatchSizeDoubles) {
  const std::string dir_path = GetDefaultFullPath("dir");
  const std::string file_name_1 = "file1.txt";
  const std::string file_path_1 = dir_path + "/" + file_name_1;
  const std::string file_name_2 = "file2.txt";
  const std::string file_path_2 = dir_path + "/" + file_name_2;
  const std::string file_name_3 = "file3.txt";
  const std::string file_path_3 = dir_path + "/" + file_name_3;
  const std::string file_name_4 = "file4.txt";
  const std::string file_path_4 = dir_path + "/" + file_name_4;

  PrepareFileSystem();
  fake_samba_->AddDirectory(dir_path);
  fake_samba_->AddFile(file_path_1);
  fake_samba_->AddFile(file_path_2);
  fake_samba_->AddFile(file_path_3);
  fake_samba_->AddFile(file_path_4);

  ReadDirProgress read_dir_progress(fake_samba_.get(),
                                    1 /* initial_batch_size*/);

  int32_t error;
  DirectoryEntryListProto entries;
  bool should_continue_read_dir =
      read_dir_progress.StartReadDir(dir_path, cache_.get(), &error, &entries);

  EXPECT_TRUE(should_continue_read_dir);

  EXPECT_EQ(1, entries.entries_size());

  should_continue_read_dir =
      read_dir_progress.ContinueReadDir(&error, &entries);

  EXPECT_TRUE(should_continue_read_dir);

  // Batch size doubles to two.
  EXPECT_EQ(2, entries.entries_size());

  should_continue_read_dir =
      read_dir_progress.ContinueReadDir(&error, &entries);

  EXPECT_FALSE(should_continue_read_dir);

  // Last remaining entry should be returned.
  EXPECT_EQ(1, entries.entries_size());
}

}  // namespace smbprovider
