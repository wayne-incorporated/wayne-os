// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "smbprovider/metadata_cache.h"

#include <base/time/tick_clock.h>

namespace smbprovider {

MetadataCache::MetadataCache(base::TickClock* tick_clock,
                             base::TimeDelta entry_lifetime,
                             Mode mode)
    : tick_clock_(tick_clock), entry_lifetime_(entry_lifetime), mode_(mode) {}

MetadataCache::~MetadataCache() = default;

void MetadataCache::AddEntry(const DirectoryEntry& entry) {
  // NowTicks() is non-decreasing so any value we get will always be at
  // at least equal to the higest version we've seen before.
  max_expiration_time_ = tick_clock_->NowTicks() + entry_lifetime_;
  cache_[entry.full_path] = CacheEntry(entry, max_expiration_time_);
}

bool MetadataCache::FindEntry(const std::string& full_path,
                              DirectoryEntry* out_entry) {
  if (!IsEnabled()) {
    return false;
  }

  auto entry_iter = cache_.find(full_path);
  if (entry_iter == cache_.end()) {
    return false;
  }

  if (IsExpired(entry_iter->second)) {
    cache_.erase(entry_iter);
    return false;
  }

  *out_entry = entry_iter->second.entry;
  return true;
}

void MetadataCache::ClearAll() {
  cache_.clear();
}

bool MetadataCache::IsEmpty() const {
  return cache_.empty();
}

bool MetadataCache::RemoveEntry(const std::string& entry_path) {
  return cache_.erase(entry_path) > 0;
}

void MetadataCache::PurgeExpiredEntries() {
  if (IsEmpty()) {
    // Nothing to do if it is already empty.
    return;
  }

  // If all entries are expired, just clear the entire map.
  if (AreAllEntriesExpired()) {
    ClearAll();
    return;
  }

  // Otherwise iterate through the map removing the expired entries.
  const base::TimeTicks threshold = tick_clock_->NowTicks();

  auto it = cache_.cbegin();
  while (it != cache_.cend()) {
    if (MetadataCache::IsExpired(it->second, threshold)) {
      it = cache_.erase(it);
    } else {
      ++it;
    }
  }
}

bool MetadataCache::IsExpired(const CacheEntry& cache_entry,
                              base::TimeTicks threshold) {
  return threshold > cache_entry.expiration_time;
}

bool MetadataCache::IsExpired(
    const MetadataCache::CacheEntry& cache_entry) const {
  return MetadataCache::IsExpired(cache_entry, tick_clock_->NowTicks());
}

bool MetadataCache::AreAllEntriesExpired() const {
  return tick_clock_->NowTicks() > max_expiration_time_;
}

bool MetadataCache::IsEnabled() const {
  return mode_ != Mode::kDisabled;
}

}  // namespace smbprovider
