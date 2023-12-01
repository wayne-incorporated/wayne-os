// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SMBPROVIDER_ITERATOR_CACHING_ITERATOR_H_
#define SMBPROVIDER_ITERATOR_CACHING_ITERATOR_H_

#include <string>
#include <utility>

#include "smbprovider/iterator/directory_iterator.h"
#include "smbprovider/metadata_cache.h"

namespace smbprovider {

// Iterator class that wraps a directory iterator and stores each
// entry in a cache as it is iterated over.
class CachingIterator {
 public:
  CachingIterator(DirectoryIterator it, MetadataCache* cache)
      : inner_it_(std::move(it)), cache_(cache) {}

  CachingIterator(const std::string& full_path,
                  SambaInterface* samba_interface,
                  MetadataCache* cache)
      : CachingIterator(DirectoryIterator(full_path, samba_interface), cache) {}

  CachingIterator(CachingIterator&& other) = default;
  CachingIterator(const CachingIterator&) = delete;
  CachingIterator& operator=(const CachingIterator&) = delete;

  ~CachingIterator() = default;

  // Initializes the iterator, setting the first value of current. Returns 0 on
  // success, error on failure. Must be called before any other operation.
  [[nodiscard]] int32_t Init() { return inner_it_.Init(); }

  // Advances current to the next entry. Returns 0 on success,
  // error on failure.
  [[nodiscard]] int32_t Next() { return inner_it_.Next(); }

  // Returns the current DirectoryEntry.
  const DirectoryEntry& Get() {
    const DirectoryEntry& entry = inner_it_.Get();
    cache_->AddEntry(entry);
    return entry;
  }

  // Returns true if there is nothing left to iterate over.
  [[nodiscard]] bool IsDone() { return inner_it_.IsDone(); }

 private:
  DirectoryIterator inner_it_;
  MetadataCache* cache_ = nullptr;  // Not owned.
};

}  // namespace smbprovider

#endif  // SMBPROVIDER_ITERATOR_CACHING_ITERATOR_H_
