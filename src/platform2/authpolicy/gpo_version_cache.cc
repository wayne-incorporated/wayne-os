// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/gpo_version_cache.h"

#include <utility>

#include "base/logging.h"
#include "base/time/clock.h"
#include "base/time/default_clock.h"

#include "authpolicy/log_colors.h"
#include "bindings/authpolicy_containers.pb.h"

namespace authpolicy {
namespace {
constexpr char kLogHeader[] = "GPO Cache: ";
}

#define LOG_START(severity) \
  LOG_IF(severity, flags_->log_caches()) << kColorCaches << kLogHeader
#define LOG_END kColorReset

GpoVersionCache::GpoVersionCache(const protos::DebugFlags* flags)
    : flags_(flags), clock_(std::make_unique<base::DefaultClock>()) {}

GpoVersionCache::~GpoVersionCache() = default;

void GpoVersionCache::Clear() {
  cache_.clear();
}

void GpoVersionCache::Add(const std::string& key, uint32_t version) {
  if (!enabled_)
    return;

  base::Time now = clock_->Now();
  cache_[key] = {version, now};
  LOG_START(INFO) << key << ": Adding version " << version << " at " << now
                  << LOG_END;
}

void GpoVersionCache::Remove(const std::string& key) {
  if (!enabled_)
    return;

  bool erased = cache_.erase(key) != 0;
  if (erased)
    LOG_START(INFO) << kLogHeader << key << ": Removing" << LOG_END;
}

bool GpoVersionCache::MayUseCachedGpo(const std::string& key,
                                      uint32_t version) {
  if (!enabled_) {
    LOG_START(INFO) << key << ": Downloading (cache turned off)" << LOG_END;
    cache_misses_for_testing_++;
    return false;
  }

  auto it = cache_.find(key);
  if (it == cache_.end()) {
    LOG_START(INFO) << key << ": Downloading (not in cache)" << LOG_END;
    cache_misses_for_testing_++;
    return false;
  }

  const CacheEntry& cache_entry = it->second;
  if (version != cache_entry.version) {
    LOG_START(INFO) << key << ": Downloading (version " << version
                    << " != cached version " << cache_entry.version << ")"
                    << LOG_END;
    cache_misses_for_testing_++;
    return false;
  }

  LOG_START(INFO) << key << ": Using cached version " << cache_entry.version
                  << LOG_END;
  cache_hits_for_testing_++;
  return true;
}

void GpoVersionCache::RemoveEntriesOlderThan(base::TimeDelta max_age) {
  base::Time now = clock_->Now();
  for (auto it = cache_.begin(); it != cache_.end(); /* empty */) {
    // Note: If the clock goes backwards for some reason, clear cache as well
    // just in case the clock was reset.
    const std::string& key = it->first;
    const CacheEntry& cache_entry = it->second;
    base::TimeDelta age = now - cache_entry.cache_time;
    if (age < base::TimeDelta() || age >= max_age) {
      LOG_START(INFO) << key << ": Removing from cache (age=" << age << ")"
                      << LOG_END;
      it = cache_.erase(it);
    } else {
      ++it;
    }
  }
}

void GpoVersionCache::SetClockForTesting(std::unique_ptr<base::Clock> clock) {
  clock_ = std::move(clock);
}

}  // namespace authpolicy
