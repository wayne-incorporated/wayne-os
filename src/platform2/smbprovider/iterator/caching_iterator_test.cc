// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/test/simple_test_tick_clock.h>
#include <gtest/gtest.h>

#include "smbprovider/fake_samba_interface.h"
#include "smbprovider/iterator/caching_iterator.h"
#include "smbprovider/iterator/directory_iterator.h"
#include "smbprovider/metadata_cache.h"
#include "smbprovider/smbprovider_test_helper.h"

namespace smbprovider {

class CachingIteratorTest : public testing::Test {
 public:
  CachingIteratorTest() {
    tick_clock_ = std::make_unique<base::SimpleTestTickClock>();
    cache_ = std::make_unique<MetadataCache>(
        tick_clock_.get(),
        base::Microseconds(kMetadataCacheLifetimeMicroseconds),
        MetadataCache::Mode::kStandard);
  }
  CachingIteratorTest(const CachingIteratorTest&) = delete;
  CachingIteratorTest& operator=(const CachingIteratorTest&) = delete;

  ~CachingIteratorTest() override = default;

 protected:
  void CreateDefaultMountRoot() {
    fake_samba_.AddDirectory(GetDefaultServer());
    fake_samba_.AddDirectory(GetDefaultMountRoot());
  }

  CachingIterator GetIterator(const std::string& full_path) {
    return CachingIterator(full_path, &fake_samba_, cache_.get());
  }

  FakeSambaInterface fake_samba_;
  std::unique_ptr<base::TickClock> tick_clock_;
  std::unique_ptr<MetadataCache> cache_;
};

TEST_F(CachingIteratorTest, NonExistentDir) {
  auto it = GetIterator("smb://non-existent-path/");
  EXPECT_EQ(ENOENT, it.Init());
}

TEST_F(CachingIteratorTest, FailsOnFile) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());
  fake_samba_.AddFile(GetAddedFullFilePath());

  auto it = GetIterator(GetAddedFullFilePath());

  EXPECT_EQ(ENOTDIR, it.Init());
}

TEST_F(CachingIteratorTest, InitSucceedsAndSetsDoneOnEmptyDirectory) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());

  auto it = GetIterator(GetAddedFullDirectoryPath());

  EXPECT_EQ(0, it.Init());
  EXPECT_TRUE(it.IsDone());
}

TEST_F(CachingIteratorTest, IteratorPopulatesTheCache) {
  CreateDefaultMountRoot();

  fake_samba_.AddDirectory(GetAddedFullDirectoryPath());

  const uint64_t expected_size = 99;
  const time_t expected_date = 888822222;
  fake_samba_.AddFile(GetAddedFullFilePath(), expected_size, expected_date);

  auto it = GetIterator(GetAddedFullDirectoryPath());
  EXPECT_EQ(0, it.Init());
  EXPECT_FALSE(it.IsDone());

  // The cache should start empty.
  EXPECT_TRUE(cache_->IsEmpty());

  // After calling Get() the cache should be populated.
  const DirectoryEntry& entry = it.Get();
  EXPECT_FALSE(cache_->IsEmpty());

  DirectoryEntry cached_entry;
  EXPECT_TRUE(cache_->FindEntry(GetAddedFullFilePath(), &cached_entry));

  // Verify the entry returned by the iterator is correct.
  EXPECT_EQ("dog.jpg", entry.name);
  EXPECT_FALSE(entry.is_directory);
  EXPECT_EQ(expected_size, entry.size);
  EXPECT_EQ(expected_date, entry.last_modified_time);

  // Verify the entry added to the cache is correct.
  EXPECT_EQ("dog.jpg", cached_entry.name);
  EXPECT_FALSE(cached_entry.is_directory);
  EXPECT_EQ(expected_size, cached_entry.size);
  EXPECT_EQ(expected_date, cached_entry.last_modified_time);

  EXPECT_EQ(0, it.Next());
  EXPECT_TRUE(it.IsDone());
}

}  // namespace smbprovider
