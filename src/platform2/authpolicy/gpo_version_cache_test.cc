// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/test/simple_test_clock.h>
#include <base/time/time.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "authpolicy/gpo_version_cache.h"
#include "bindings/authpolicy_containers.pb.h"

namespace {
constexpr char kKey[] = "GUID-M";

constexpr int kVersion1 = 1;
constexpr int kVersion2 = 2;

constexpr base::TimeDelta kTwoDays = base::Days(2);
constexpr base::TimeDelta kThreeDays = base::Days(3);
constexpr base::TimeDelta kMinusOneSecond = base::Seconds(-1);
}  // namespace

namespace authpolicy {

class GpoVersionCacheTest : public ::testing::Test {
 public:
  GpoVersionCacheTest() : cache_(&flags_) {
    cache_.SetClockForTesting(std::make_unique<base::SimpleTestClock>());
    flags_.set_log_caches(true);
  }
  GpoVersionCacheTest(const GpoVersionCacheTest&) = delete;
  GpoVersionCacheTest& operator=(const GpoVersionCacheTest&) = delete;

  ~GpoVersionCacheTest() override {}

 protected:
  GpoVersionCache cache_;
  base::SimpleTestClock* clock() {
    return static_cast<base::SimpleTestClock*>(cache_.clock());
  }

 private:
  protos::DebugFlags flags_;
};

TEST_F(GpoVersionCacheTest, AddingAndRemoving) {
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion1));

  cache_.Add(kKey, kVersion1);
  EXPECT_TRUE(cache_.MayUseCachedGpo(kKey, kVersion1));
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion2));

  cache_.Add(kKey, kVersion2);
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion1));
  EXPECT_TRUE(cache_.MayUseCachedGpo(kKey, kVersion2));

  cache_.Remove(kKey);
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion2));
}

TEST_F(GpoVersionCacheTest, PurgeExpiredEntries) {
  cache_.Add(kKey, kVersion1);
  EXPECT_TRUE(cache_.MayUseCachedGpo(kKey, kVersion1));

  // Entry just got added, it's not older than 3 days.
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_TRUE(cache_.MayUseCachedGpo(kKey, kVersion1));

  // Advance 2 days -> entry is NOT older than 3 days and stays in cache.
  clock()->Advance(kTwoDays);
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_TRUE(cache_.MayUseCachedGpo(kKey, kVersion1));

  // Advance another 2 days (4 days total) -> entry is older than 3 days and
  // gets purged.
  clock()->Advance(kTwoDays);
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion1));
}

TEST_F(GpoVersionCacheTest, PurgeEntriesWhenTimeGoesBackwards) {
  cache_.Add(kKey, kVersion1);
  clock()->Advance(kMinusOneSecond);
  EXPECT_TRUE(cache_.MayUseCachedGpo(kKey, kVersion1));
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion1));
}

TEST_F(GpoVersionCacheTest, ClearCache) {
  cache_.Add(kKey, kVersion1);
  EXPECT_TRUE(cache_.MayUseCachedGpo(kKey, kVersion1));
  cache_.Clear();
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion1));
}

TEST_F(GpoVersionCacheTest, DisableCache) {
  cache_.Add(kKey, kVersion1);
  EXPECT_TRUE(cache_.MayUseCachedGpo(kKey, kVersion1));

  cache_.SetEnabled(false);

  // MayUseCachedGpo() always returns false.
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion1));

  // Add() and Remove() are ignored.
  cache_.Add(kKey, kVersion2);
  cache_.Remove(kKey);
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion1));
  EXPECT_FALSE(cache_.MayUseCachedGpo(kKey, kVersion2));

  cache_.SetEnabled(true);
  EXPECT_TRUE(cache_.MayUseCachedGpo(kKey, kVersion1));
}

}  // namespace authpolicy
