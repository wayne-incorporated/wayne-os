// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/test/simple_test_tick_clock.h>
#include <gtest/gtest.h>

#include "smbprovider/constants.h"
#include "smbprovider/metadata_cache.h"

namespace smbprovider {

namespace {
bool AreEntriesEqual(const DirectoryEntry& lhs, const DirectoryEntry& rhs) {
  return lhs.name == rhs.name && lhs.full_path == rhs.full_path &&
         lhs.size == rhs.size &&
         lhs.last_modified_time == rhs.last_modified_time &&
         lhs.is_directory == rhs.is_directory;
}
}  // namespace

class MetadataCacheTest : public testing::Test {
 public:
  MetadataCacheTest() {
    cache_lifetime_ = base::Microseconds(kMetadataCacheLifetimeMicroseconds);
    tick_clock_ = std::make_unique<base::SimpleTestTickClock>();
    cache_ = std::make_unique<MetadataCache>(tick_clock_.get(), cache_lifetime_,
                                             MetadataCache::Mode::kStandard);
  }
  MetadataCacheTest(const MetadataCacheTest&) = delete;
  MetadataCacheTest& operator=(const MetadataCacheTest&) = delete;

  ~MetadataCacheTest() override = default;

 protected:
  base::TimeDelta cache_lifetime_;
  std::unique_ptr<MetadataCache> cache_;
  std::unique_ptr<base::SimpleTestTickClock> tick_clock_;
};

TEST_F(MetadataCacheTest, FindOnEmptyCache) {
  DirectoryEntry found_entry;
  EXPECT_FALSE(cache_->FindEntry("smb://server/share/not/found", &found_entry));
}

TEST_F(MetadataCacheTest, AddAndFindEntry) {
  const std::string name = "file";
  const std::string full_path = "smb://server/share/dir/" + name;

  DirectoryEntry found_entry;
  EXPECT_FALSE(cache_->FindEntry(full_path, &found_entry));

  const int64_t expected_size = 1234;
  const int64_t expected_date = 9999999;
  const DirectoryEntry expected_entry(false /* is_directory */, name, full_path,
                                      expected_size, expected_date);
  cache_->AddEntry(expected_entry);
  EXPECT_FALSE(cache_->IsEmpty());
  EXPECT_TRUE(cache_->FindEntry(full_path, &found_entry));
  EXPECT_TRUE(AreEntriesEqual(expected_entry, found_entry));

  // Verify it can be found again.
  DirectoryEntry found_entry2;
  EXPECT_TRUE(cache_->FindEntry(full_path, &found_entry2));
  EXPECT_TRUE(AreEntriesEqual(expected_entry, found_entry2));
}

TEST_F(MetadataCacheTest, AddAndFindEntryOnExpirationBoundary) {
  const std::string name = "file";
  const std::string full_path = "smb://server/share/dir/" + name;

  DirectoryEntry found_entry;
  EXPECT_FALSE(cache_->FindEntry(full_path, &found_entry));

  const int64_t expected_size = 1234;
  const int64_t expected_date = 9999999;
  const DirectoryEntry expected_entry(false /* is_directory */, name, full_path,
                                      expected_size, expected_date);
  cache_->AddEntry(expected_entry);
  EXPECT_FALSE(cache_->IsEmpty());
  EXPECT_TRUE(cache_->FindEntry(full_path, &found_entry));
  EXPECT_TRUE(AreEntriesEqual(expected_entry, found_entry));

  // Advance the clock to the last tick where it is still valid.
  tick_clock_->Advance(base::Microseconds(kMetadataCacheLifetimeMicroseconds));

  // Verify it can be found again.
  DirectoryEntry found_entry2;
  EXPECT_TRUE(cache_->FindEntry(full_path, &found_entry2));
  EXPECT_TRUE(AreEntriesEqual(expected_entry, found_entry2));
  EXPECT_FALSE(cache_->IsEmpty());

  // Advance one more tick to expire it.
  tick_clock_->Advance(base::Microseconds(1));

  // Verify it is not found any more and removed from cache.
  DirectoryEntry found_entry3;
  EXPECT_FALSE(cache_->FindEntry(full_path, &found_entry3));
  EXPECT_TRUE(cache_->IsEmpty());
}

TEST_F(MetadataCacheTest, PurgeExpiresEntries) {
  const std::string name = "file";
  const std::string full_path = "smb://server/share/dir/" + name;

  DirectoryEntry found_entry;
  EXPECT_FALSE(cache_->FindEntry(full_path, &found_entry));

  const int64_t expected_size = 1234;
  const int64_t expected_date = 9999999;
  const DirectoryEntry expected_entry(false /* is_directory */, name, full_path,
                                      expected_size, expected_date);
  cache_->AddEntry(expected_entry);
  EXPECT_FALSE(cache_->IsEmpty());
  EXPECT_TRUE(cache_->FindEntry(full_path, &found_entry));
  EXPECT_TRUE(AreEntriesEqual(expected_entry, found_entry));

  // Advance the clock to the last tick where it is still valid.
  tick_clock_->Advance(base::Microseconds(kMetadataCacheLifetimeMicroseconds));

  // Purge the cache but it shouldn't expire anything
  cache_->PurgeExpiredEntries();
  EXPECT_FALSE(cache_->IsEmpty());

  // Verify it can be found again.
  DirectoryEntry found_entry2;
  EXPECT_TRUE(cache_->FindEntry(full_path, &found_entry2));
  EXPECT_TRUE(AreEntriesEqual(expected_entry, found_entry2));
  EXPECT_FALSE(cache_->IsEmpty());

  // Advance one more tick to expire it.
  tick_clock_->Advance(base::Microseconds(1));

  // Purging should now remove the entry.
  cache_->PurgeExpiredEntries();
  EXPECT_TRUE(cache_->IsEmpty());
}

TEST_F(MetadataCacheTest, IsEmptyOnNewCache) {
  EXPECT_TRUE(cache_->IsEmpty());
}

TEST_F(MetadataCacheTest, ClearOnEmptyCache) {
  EXPECT_TRUE(cache_->IsEmpty());
  cache_->ClearAll();
  EXPECT_TRUE(cache_->IsEmpty());
}

TEST_F(MetadataCacheTest, ClearRemovesItems) {
  EXPECT_TRUE(cache_->IsEmpty());

  const std::string name = "path";
  const std::string full_path = "smb://server/share/some/" + name;
  cache_->AddEntry(DirectoryEntry(false /* is_directory */, name, full_path,
                                  1234 /* size */, 999999 /* date */));

  EXPECT_FALSE(cache_->IsEmpty());
  cache_->ClearAll();
  EXPECT_TRUE(cache_->IsEmpty());
}

TEST_F(MetadataCacheTest, RemoveItemExplicitly) {
  EXPECT_TRUE(cache_->IsEmpty());

  const std::string name = "path";
  const std::string full_path = "smb://server/share/some/" + name;
  cache_->AddEntry(DirectoryEntry(false /* is_directory */, name, full_path,
                                  1234 /* size */, 999999 /* date */));

  EXPECT_FALSE(cache_->IsEmpty());
  EXPECT_TRUE(cache_->RemoveEntry(full_path));
  EXPECT_TRUE(cache_->IsEmpty());
}

TEST_F(MetadataCacheTest, RemoveItemThatDoesntExist) {
  EXPECT_TRUE(cache_->IsEmpty());

  const std::string name = "path";
  const std::string full_path = "smb://server/share/some/" + name;
  cache_->AddEntry(DirectoryEntry(false /* is_directory */, name, full_path,
                                  1234 /* size */, 999999 /* date */));

  EXPECT_FALSE(cache_->IsEmpty());

  // Removal of an entry that doesn't exist returns false and
  // doesn't change the cache.
  EXPECT_FALSE(cache_->RemoveEntry(full_path + "2"));
  EXPECT_FALSE(cache_->IsEmpty());
  DirectoryEntry entry;
  EXPECT_TRUE(cache_->FindEntry(full_path, &entry));
}

}  // namespace smbprovider
