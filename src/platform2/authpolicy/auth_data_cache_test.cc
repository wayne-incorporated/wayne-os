// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/auth_data_cache.h"

#include <memory>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/test/simple_test_clock.h>
#include <gtest/gtest.h>

#include "bindings/authpolicy_containers.pb.h"

namespace {

constexpr char kRealm1[] = "realm_1";
constexpr char kRealm2[] = "realm_2";
constexpr char kRealm3[] = "realm_3";

constexpr char kWorkgroup[] = "wokgroup";
constexpr char kDcName[] = "dc_name";
constexpr char kKdcIp[] = "kdc_ip";

constexpr bool kIsAffiliated = true;

constexpr char kInvalidData[] = "data'); DROP TABLE DataCache;--";

constexpr char kNonExistingFile[] = "does_not_exist";

constexpr base::TimeDelta kTwoDays = base::Days(2);
constexpr base::TimeDelta kThreeDays = base::Days(3);
constexpr base::TimeDelta kEightDays = base::Days(8);
constexpr base::TimeDelta kMinusOneSecond = base::Seconds(-1);

}  // namespace

namespace authpolicy {

class AuthDataCacheTest : public ::testing::Test {
 public:
  AuthDataCacheTest() {
    // Create path for testing serialization.
    CHECK(base::CreateNewTempDirectory("" /* prefix (ignored) */, &tmp_path_));
    cache_.SetClockForTesting(std::make_unique<base::SimpleTestClock>());
    flags_.set_log_caches(true);
  }
  AuthDataCacheTest(const AuthDataCacheTest&) = delete;
  AuthDataCacheTest& operator=(const AuthDataCacheTest&) = delete;

  ~AuthDataCacheTest() override = default;

 protected:
  base::SimpleTestClock* clock() {
    return static_cast<base::SimpleTestClock*>(cache_.clock());
  }

  protos::DebugFlags flags_;
  AuthDataCache cache_{&flags_};
  base::FilePath tmp_path_;
};

TEST_F(AuthDataCacheTest, GetSetWorkgroup) {
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  ASSERT_TRUE(cache_.GetWorkgroup(kRealm1));
  EXPECT_EQ(kWorkgroup, *cache_.GetWorkgroup(kRealm1));
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm2));
}

TEST_F(AuthDataCacheTest, GetSetKdcIp) {
  EXPECT_FALSE(cache_.GetKdcIp(kRealm1));
  cache_.SetKdcIp(kRealm1, kKdcIp);
  ASSERT_TRUE(cache_.GetKdcIp(kRealm1));
  EXPECT_EQ(kKdcIp, *cache_.GetKdcIp(kRealm1));
  EXPECT_FALSE(cache_.GetKdcIp(kRealm2));
}

TEST_F(AuthDataCacheTest, GetSetDcName) {
  EXPECT_FALSE(cache_.GetDcName(kRealm1));
  cache_.SetDcName(kRealm1, kDcName);
  ASSERT_TRUE(cache_.GetDcName(kRealm1));
  EXPECT_EQ(kDcName, *cache_.GetDcName(kRealm1));
  EXPECT_FALSE(cache_.GetDcName(kRealm2));
}

TEST_F(AuthDataCacheTest, GetSetIsAffiliated) {
  EXPECT_FALSE(cache_.GetIsAffiliated(kRealm1));
  cache_.SetIsAffiliated(kRealm1, kIsAffiliated);
  ASSERT_TRUE(cache_.GetIsAffiliated(kRealm1));
  EXPECT_EQ(kIsAffiliated, *cache_.GetIsAffiliated(kRealm1));
  EXPECT_FALSE(cache_.GetIsAffiliated(kRealm2));
}

TEST_F(AuthDataCacheTest, LoadFailsFileDoesNotExist) {
  EXPECT_FALSE(cache_.Load(base::FilePath(kNonExistingFile)));
}

TEST_F(AuthDataCacheTest, LoadFailsInvalidData) {
  base::FilePath data_path = tmp_path_.Append("test");
  int data_size = strlen(kInvalidData);
  ASSERT_EQ(data_size, base::WriteFile(data_path, kInvalidData, data_size));
  EXPECT_FALSE(cache_.Load(data_path));
}

TEST_F(AuthDataCacheTest, FailedLoadClearsData) {
  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));
  EXPECT_FALSE(cache_.Load(base::FilePath(kNonExistingFile)));
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
}

TEST_F(AuthDataCacheTest, SaveLoadSucceeds) {
  // Create a separate cache and set some data.
  AuthDataCache other_cache(&flags_);
  other_cache.SetWorkgroup(kRealm1, kWorkgroup);
  other_cache.SetKdcIp(kRealm1, kKdcIp);
  other_cache.SetDcName(kRealm1, kDcName);
  other_cache.SetIsAffiliated(kRealm1, kIsAffiliated);

  // Save the separate cache to file.
  base::FilePath data_path = tmp_path_.Append("test");
  EXPECT_FALSE(base::PathExists(data_path));
  EXPECT_TRUE(other_cache.Save(data_path));
  EXPECT_TRUE(base::PathExists(data_path));

  // Load data into |cache_|.
  EXPECT_TRUE(cache_.Load(data_path));

  ASSERT_TRUE(cache_.GetWorkgroup(kRealm1));
  ASSERT_TRUE(cache_.GetKdcIp(kRealm1));
  ASSERT_TRUE(cache_.GetDcName(kRealm1));
  ASSERT_TRUE(cache_.GetIsAffiliated(kRealm1));

  EXPECT_EQ(kWorkgroup, *cache_.GetWorkgroup(kRealm1));
  EXPECT_EQ(kKdcIp, *cache_.GetKdcIp(kRealm1));
  EXPECT_EQ(kDcName, *cache_.GetDcName(kRealm1));
  EXPECT_EQ(kIsAffiliated, *cache_.GetIsAffiliated(kRealm1));
}

TEST_F(AuthDataCacheTest, SettersCanBeDisabled) {
  cache_.SetEnabled(false);

  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  cache_.SetKdcIp(kRealm1, kKdcIp);
  cache_.SetDcName(kRealm1, kDcName);
  cache_.SetIsAffiliated(kRealm1, kIsAffiliated);

  cache_.SetEnabled(true);

  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
  EXPECT_FALSE(cache_.GetKdcIp(kRealm1));
  EXPECT_FALSE(cache_.GetDcName(kRealm1));
  EXPECT_FALSE(cache_.GetIsAffiliated(kRealm1));
}

TEST_F(AuthDataCacheTest, GettersCanBeDisabled) {
  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  cache_.SetKdcIp(kRealm1, kKdcIp);
  cache_.SetDcName(kRealm1, kDcName);
  cache_.SetIsAffiliated(kRealm1, kIsAffiliated);

  cache_.SetEnabled(false);

  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
  EXPECT_FALSE(cache_.GetKdcIp(kRealm1));
  EXPECT_FALSE(cache_.GetDcName(kRealm1));
  EXPECT_FALSE(cache_.GetIsAffiliated(kRealm1));

  cache_.SetEnabled(true);

  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));
  EXPECT_TRUE(cache_.GetKdcIp(kRealm1));
  EXPECT_TRUE(cache_.GetDcName(kRealm1));
  EXPECT_TRUE(cache_.GetIsAffiliated(kRealm1));
}

TEST_F(AuthDataCacheTest, LoadSaveCanBeDisabled) {
  base::FilePath data_path1 = tmp_path_.Append("test1");
  base::FilePath data_path2 = tmp_path_.Append("test2");

  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  EXPECT_TRUE(cache_.Save(data_path1));
  EXPECT_TRUE(base::PathExists(data_path1));

  cache_.SetEnabled(false);

  // Save() always returns true, but doesn't do anything.
  EXPECT_TRUE(cache_.Save(data_path2));
  EXPECT_FALSE(base::PathExists(data_path2));

  cache_.Clear();

  // Load() always returns true, but doesn't do anything.
  EXPECT_TRUE(cache_.Load(data_path2));
  EXPECT_TRUE(cache_.Load(data_path1));

  // Make sure the cache didn't load data_path1.
  cache_.SetEnabled(true);
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
}

TEST_F(AuthDataCacheTest, PurgeExpiredEntries) {
  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));

  // Entry just got added, it's not older than 3 days.
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));

  // Advance 2 days -> entry is NOT older than 3 days and stays in cache.
  clock()->Advance(kTwoDays);
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));

  // Advance another 2 days (4 days total) -> entry is older than 3 days and
  // gets purged.
  clock()->Advance(kTwoDays);
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
}

TEST_F(AuthDataCacheTest, DoesNotResetTimeInSetter) {
  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  clock()->Advance(kTwoDays);

  // This should not reset the cache time.
  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  clock()->Advance(kTwoDays);

  // This should remove the entry since it's now 4 days old.
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
}

// Once RemoveEntriesOlderThan() purges entries, the cache should memorize time
// on the next Set() call.
TEST_F(AuthDataCacheTest, PurgeResetsTime) {
  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  clock()->Advance(kTwoDays);
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));
  clock()->Advance(kTwoDays);
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));

  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  clock()->Advance(kTwoDays);
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));
  clock()->Advance(kTwoDays);
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
}

TEST_F(AuthDataCacheTest, PurgeEntriesWhenTimeGoesBackwards) {
  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  clock()->Advance(kMinusOneSecond);
  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));
  cache_.RemoveEntriesOlderThan(kThreeDays);
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
}

TEST_F(AuthDataCacheTest, KeepsTimeByRealm) {
  cache_.SetWorkgroup(kRealm1, kWorkgroup);
  clock()->Advance(kThreeDays);

  // State: kRealm1 (3 days old)
  cache_.RemoveEntriesOlderThan(kEightDays);
  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));
  EXPECT_FALSE(cache_.GetDcName(kRealm2));
  EXPECT_FALSE(cache_.GetKdcIp(kRealm3));

  cache_.SetDcName(kRealm2, kDcName);
  clock()->Advance(kThreeDays);

  // State: kRealm1 (6d), kRealm2 (3d)
  cache_.RemoveEntriesOlderThan(kEightDays);
  EXPECT_TRUE(cache_.GetWorkgroup(kRealm1));
  EXPECT_TRUE(cache_.GetDcName(kRealm2));
  EXPECT_FALSE(cache_.GetKdcIp(kRealm3));

  cache_.SetKdcIp(kRealm3, kKdcIp);
  clock()->Advance(kThreeDays);

  // State: kRealm1 (9d, gets purged), kRealm2 (6d), kRealm3 (3d)
  cache_.RemoveEntriesOlderThan(kEightDays);
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
  EXPECT_TRUE(cache_.GetDcName(kRealm2));
  EXPECT_TRUE(cache_.GetKdcIp(kRealm3));

  clock()->Advance(kThreeDays);

  // State: kRealm2 (9d, gets purged), kRealm3 (6d)
  cache_.RemoveEntriesOlderThan(kEightDays);
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
  EXPECT_FALSE(cache_.GetDcName(kRealm2));
  EXPECT_TRUE(cache_.GetKdcIp(kRealm3));

  clock()->Advance(kThreeDays);

  // State: kRealm3 (9d, gets purged)
  cache_.RemoveEntriesOlderThan(kEightDays);
  EXPECT_FALSE(cache_.GetWorkgroup(kRealm1));
  EXPECT_FALSE(cache_.GetDcName(kRealm2));
  EXPECT_FALSE(cache_.GetKdcIp(kRealm3));
}

}  // namespace authpolicy
