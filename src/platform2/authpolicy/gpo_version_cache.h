// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_GPO_VERSION_CACHE_H_
#define AUTHPOLICY_GPO_VERSION_CACHE_H_

#include <map>
#include <memory>
#include <string>

#include "base/time/time.h"

namespace base {
class Clock;
class FilePath;
}  // namespace base

namespace authpolicy {

namespace protos {
class DebugFlags;
}

// Simple cache that keeps track of GPO versions.
class GpoVersionCache {
 public:
  // |flags| is a non-owned pointer to DebugFlags flags (the class listens to
  // flags->log_caches() to toggle logging).
  explicit GpoVersionCache(const protos::DebugFlags* flags);
  GpoVersionCache(const GpoVersionCache&) = delete;
  GpoVersionCache& operator=(const GpoVersionCache&) = delete;

  ~GpoVersionCache();

  // Clears the cache.
  void Clear();

  // Caches the |version| of the GPO with given |key| and keeps track of the
  // time for RemoveEntriesOlderThan(). Any |key| can be used, but in practice
  // it's going to be something like "GUID-U" or "GUID-M", depending on whether
  // it's user or machine policy, where GUID is the GPO's objectGuid.
  void Add(const std::string& key, uint32_t version);

  // Removes the GPO with given |key| from the cache. Does nothing if |key| does
  // not exist.
  void Remove(const std::string& key);

  // Returns true if the GPO with given |key| is in the cache and its version
  // matches the given target |version|.
  bool MayUseCachedGpo(const std::string& key, uint32_t version);

  // Removes all cache entriers older than |max_age|.
  void RemoveEntriesOlderThan(base::TimeDelta max_age);

  // Overrides the clock used for purging old cache entries.
  void SetClockForTesting(std::unique_ptr<base::Clock> clock);

  base::Clock* clock() { return clock_.get(); }

  // Turns the cache on or off. While set to false, MayUseCachedGpo() always
  // returns false and Add() and Remove() do nothing.
  void SetEnabled(bool enabled) { enabled_ = enabled; }
  bool IsEnabled() const { return enabled_; }

  int cache_hits_for_testing() const { return cache_hits_for_testing_; }
  int cache_misses_for_testing() const { return cache_misses_for_testing_; }

 private:
  struct CacheEntry {
    uint32_t version;       // GPO version (user/machine depending on scope).
    base::Time cache_time;  // Time when Add() was called last.
  };

  // Maps GPO path to CacheEntry.
  std::map<std::string, CacheEntry> cache_;

  // Pointer to debug flags, not owned.
  const protos::DebugFlags* flags_;

  // Clock to get cache time, can be overridden for tests.
  std::unique_ptr<base::Clock> clock_;

  // While set to false, MayUseCachedGpo() always returns false and Add and
  // Remove do nothing.
  bool enabled_ = true;

  // Counters for the number of times MayUseCachedGpo() returns true (hits) and
  // false (misses) for testing.
  int cache_hits_for_testing_ = 0;
  int cache_misses_for_testing_ = 0;
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_GPO_VERSION_CACHE_H_
