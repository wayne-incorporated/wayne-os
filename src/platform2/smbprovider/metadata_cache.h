// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_METADATA_CACHE_H_
#define SMBPROVIDER_METADATA_CACHE_H_

#include <string>
#include <unordered_map>

#include <base/time/time.h>

#include "smbprovider/proto.h"

namespace base {
class TickClock;
}

namespace smbprovider {

// Maintains a cache of file and directory metadata. This is the data
// that is returned by stat(); name, entry type, size, date modified.
//
// The libsmbclient API can return all metadata while enumerating a
// directory, but the Chrome FileSystemProvider API makes per entry
// requests for metadata. This cache will store the results found
// when reading a directory, then use the cache to attempt to satisfy
// requests for metadata.
class MetadataCache {
 public:
  enum class Mode {
    kStandard,  // Standard Cache behavior.
    kDisabled   // All lookups are cache misses.
  };

  // |entry_lifetime| determines how long an entry remains valid in the cache.
  MetadataCache(base::TickClock* tick_clock,
                base::TimeDelta entry_lifetime,
                Mode mode);
  MetadataCache(const MetadataCache&) = delete;
  MetadataCache& operator=(const MetadataCache&) = delete;

  ~MetadataCache();

  MetadataCache& operator=(MetadataCache&& other) = default;

  // Adds an entry to the cache.
  void AddEntry(const DirectoryEntry& entry);

  // Finds an entry at |full_path|. If found, returns true and out_entry
  // is set. |full_path| is a full smb url. If an entry is found but it
  // is expired, it is removed from the cache.
  bool FindEntry(const std::string& full_path, DirectoryEntry* out_entry);

  // Deletes all entries from the cache.
  void ClearAll();

  // Returns true if the cache is empty.
  bool IsEmpty() const;

  // Removes the entry at |entry_path| from the cache. |entry_cache| is a
  // full smb url.
  bool RemoveEntry(const std::string& entry_path);

  // Removes all entries in the cache that have expired.
  void PurgeExpiredEntries();

 private:
  struct CacheEntry {
    CacheEntry() = default;
    CacheEntry(const DirectoryEntry& entry, base::TimeTicks expiration_time)
        : entry(entry), expiration_time(expiration_time) {}
    CacheEntry(const CacheEntry&) = delete;
    CacheEntry& operator=(const CacheEntry&) = delete;

    CacheEntry& operator=(CacheEntry&& other) = default;

    DirectoryEntry entry;
    base::TimeTicks expiration_time;
  };

  // Returns true if the expiration time of this entry has passed.
  bool IsExpired(const CacheEntry& cache_entry) const;
  static bool IsExpired(const CacheEntry& cache_entry,
                        base::TimeTicks threshold);

  // Returns true if all the entries in the cache are expired.
  bool AreAllEntriesExpired() const;

  // Returns true if the cache should act as a cache.
  bool IsEnabled() const;

  std::unordered_map<std::string, CacheEntry> cache_;
  base::TickClock* tick_clock_;  // Not owned
  base::TimeDelta entry_lifetime_;
  base::TimeTicks max_expiration_time_;
  Mode mode_;
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_METADATA_CACHE_H_
