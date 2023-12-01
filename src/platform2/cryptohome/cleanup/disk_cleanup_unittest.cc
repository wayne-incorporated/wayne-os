// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/cleanup/disk_cleanup.h"

#include <algorithm>
#include <optional>
#include <string>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/no_destructor.h>
#include <brillo/cryptohome.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/cleanup/mock_disk_cleanup_routines.h"
#include "cryptohome/cleanup/mock_user_oldest_activity_timestamp_manager.h"
#include "cryptohome/filesystem_layout.h"
#include "cryptohome/mock_platform.h"
#include "cryptohome/storage/mock_homedirs.h"
#include "cryptohome/username.h"

using ::testing::_;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::SetArgPointee;
using ::testing::StrictMock;

namespace cryptohome {
namespace {

struct TestHomedir {
  ObfuscatedUsername obfuscated;
  base::Time::Exploded time;
};

// Note, the order is important. These should be oldest to newest.
const std::vector<TestHomedir>& GetTestHomedirs() {
  static base::NoDestructor<std::vector<TestHomedir>> kValue(
      std::vector<TestHomedir>{
          {ObfuscatedUsername("d5510a8dda6d743c46dadd979a61ae5603529742"),
           {2011, 1, 6, 1}},
          {ObfuscatedUsername("8f995cdee8f0711fd32e1cf6246424002c483d47"),
           {2011, 2, 2, 1}},
          {ObfuscatedUsername("973b9640e86f6073c6b6e2759ff3cf3084515e61"),
           {2011, 3, 2, 1}},
          {ObfuscatedUsername("60a354e3402f73ff4503b5d2efc5be53bc72be4d"),
           {2011, 4, 5, 1}}});
  return *kValue;
}

ACTION_P(SetEphemeralSettings, ephemeral_settings) {
  *arg0 = ephemeral_settings;
  return true;
}
}  // namespace

class DiskCleanupTest : public ::testing::Test {
 public:
  DiskCleanupTest() = default;

  void SetUp() override {
    cleanup_ = std::make_unique<DiskCleanup>(&platform_, &homedirs_,
                                             &timestamp_manager_);

    cleanup_routines_ = new StrictMock<MockDiskCleanupRoutines>;
    cleanup_->set_routines_for_testing(cleanup_routines_);

    for (const auto& hd : GetTestHomedirs()) {
      base::Time t;
      CHECK(base::Time::FromUTCExploded(hd.time, &t));
      homedir_times_.push_back(t);

      EXPECT_CALL(timestamp_manager_,
                  GetLastUserActivityTimestamp(hd.obfuscated))
          .WillRepeatedly(Return(t));
    }

    EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(base::Time()));

    policy::DevicePolicy::EphemeralSettings ephemeral_settings;
    ephemeral_settings.global_ephemeral_users_enabled = false;
    EXPECT_CALL(homedirs_, GetEphemeralSettings(_))
        .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));
    EXPECT_CALL(homedirs_, RemoveCryptohomesBasedOnPolicy())
        .WillRepeatedly(Return(HomeDirs::CryptohomesRemovedStatus::kNone));
    EXPECT_CALL(homedirs_, GetOwner(_)).WillRepeatedly(Return(false));
    EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
    EXPECT_CALL(homedirs_, DmcryptCacheContainerExists(_))
        .WillRepeatedly(Return(true));
  }

 protected:
  std::vector<HomeDirs::HomeDir> unmounted_homedirs() {
    std::vector<HomeDirs::HomeDir> ret;

    std::transform(std::begin(GetTestHomedirs()), std::end(GetTestHomedirs()),
                   std::back_inserter(ret),
                   [](const TestHomedir& hd) -> HomeDirs::HomeDir {
                     HomeDirs::HomeDir dir;
                     dir.obfuscated = hd.obfuscated;
                     dir.is_mounted = false;
                     return dir;
                   });

    // Make sure users are not already sorted.
    std::next_permutation(
        ret.begin(), ret.end(),
        [](struct HomeDirs::HomeDir& a, struct HomeDirs::HomeDir& b) {
          return a.obfuscated < b.obfuscated;
        });

    return ret;
  }

  std::vector<HomeDirs::HomeDir> mounted_homedirs() {
    std::vector<HomeDirs::HomeDir> ret = unmounted_homedirs();

    for (auto& dir : ret)
      dir.is_mounted = true;

    return ret;
  }

  int disk_space_queries(int cleanups) {
    // call from FreeDiskSpace
    // (GetTestHomedirs().size() + 1) for each step
    // -1 to allow control over next cleanup step

    return cleanups * (GetTestHomedirs().size() + 1);
  }

  StrictMock<MockPlatform> platform_;
  StrictMock<MockHomeDirs> homedirs_;
  StrictMock<MockUserOldestActivityTimestampManager> timestamp_manager_;
  StrictMock<MockDiskCleanupRoutines>* cleanup_routines_;
  std::unique_ptr<DiskCleanup> cleanup_;

  std::vector<base::Time> homedir_times_;
};

TEST_F(DiskCleanupTest, AmountOfFreeDiskSpace) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillOnce(Return(5));

  auto val = cleanup_->AmountOfFreeDiskSpace();

  ASSERT_TRUE(val);
  EXPECT_EQ(val.value(), 5);
}

TEST_F(DiskCleanupTest, AmountOfFreeDiskSpaceError) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillOnce(Return(-1));

  auto val = cleanup_->AmountOfFreeDiskSpace();

  EXPECT_FALSE(val);
}

TEST_F(DiskCleanupTest, GetFreeDiskSpaceState) {
  cleanup_->set_target_free_space(20);
  cleanup_->set_cleanup_threshold(10);
  cleanup_->set_aggressive_cleanup_threshold(5);
  cleanup_->set_critical_cleanup_threshold(2);

  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(std::nullopt),
            DiskCleanup::FreeSpaceState::kError);

  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(0),
            DiskCleanup::FreeSpaceState::kNeedCriticalCleanup);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(4),
            DiskCleanup::FreeSpaceState::kNeedAggressiveCleanup);

  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(5),
            DiskCleanup::FreeSpaceState::kNeedNormalCleanup);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(9),
            DiskCleanup::FreeSpaceState::kNeedNormalCleanup);

  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(10),
            DiskCleanup::FreeSpaceState::kAboveThreshold);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(19),
            DiskCleanup::FreeSpaceState::kAboveThreshold);

  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(20),
            DiskCleanup::FreeSpaceState::kAboveTarget);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(1000),
            DiskCleanup::FreeSpaceState::kAboveTarget);
}

TEST_F(DiskCleanupTest, GetFreeDiskSpaceStatePlatform) {
  cleanup_->set_target_free_space(20);
  cleanup_->set_cleanup_threshold(10);
  cleanup_->set_aggressive_cleanup_threshold(5);
  cleanup_->set_critical_cleanup_threshold(2);

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillOnce(Return(-1))
      .WillOnce(Return(0))
      .WillOnce(Return(1))
      .WillOnce(Return(4))
      .WillOnce(Return(5))
      .WillOnce(Return(9))
      .WillOnce(Return(10))
      .WillOnce(Return(19))
      .WillOnce(Return(20))
      .WillOnce(Return(1000));

  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kError);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kNeedCriticalCleanup);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kNeedCriticalCleanup);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kNeedAggressiveCleanup);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kNeedNormalCleanup);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kNeedNormalCleanup);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kAboveThreshold);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kAboveThreshold);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kAboveTarget);
  EXPECT_EQ(cleanup_->GetFreeDiskSpaceState(),
            DiskCleanup::FreeSpaceState::kAboveTarget);
}

TEST_F(DiskCleanupTest, HasTargetFreeSpace) {
  cleanup_->set_target_free_space(10);

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillOnce(Return(-1))
      .WillOnce(Return(0))
      .WillOnce(Return(9))
      .WillOnce(Return(10))
      .WillOnce(Return(1000));

  EXPECT_FALSE(cleanup_->HasTargetFreeSpace());
  EXPECT_FALSE(cleanup_->HasTargetFreeSpace());
  EXPECT_FALSE(cleanup_->HasTargetFreeSpace());
  EXPECT_TRUE(cleanup_->HasTargetFreeSpace());
  EXPECT_TRUE(cleanup_->HasTargetFreeSpace());
}

TEST_F(DiskCleanupTest, IsFreeableDiskSpaceAvailableConsumerOwned) {
  EXPECT_CALL(homedirs_, enterprise_owned()).WillOnce(Return(false));

  EXPECT_FALSE(cleanup_->IsFreeableDiskSpaceAvailable());
}

TEST_F(DiskCleanupTest, IsFreeableDiskSpaceAvailable) {
  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(true));

  std::vector<HomeDirs::HomeDir> one_unmounted = mounted_homedirs();
  one_unmounted[2].is_mounted = false;

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillOnce(Return(mounted_homedirs()))
      .WillOnce(Return(one_unmounted))
      .WillOnce(Return(unmounted_homedirs()));

  EXPECT_FALSE(cleanup_->IsFreeableDiskSpaceAvailable());
  EXPECT_TRUE(cleanup_->IsFreeableDiskSpaceAvailable());
  EXPECT_TRUE(cleanup_->IsFreeableDiskSpaceAvailable());
}

TEST_F(DiskCleanupTest, EphemeralUsersHomedirs) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCleanup - 1));
  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(mounted_homedirs()));

  policy::DevicePolicy::EphemeralSettings ephemeral_settings;
  ephemeral_settings.global_ephemeral_users_enabled = true;
  EXPECT_CALL(homedirs_, GetEphemeralSettings(_))
      .WillRepeatedly(SetEphemeralSettings(ephemeral_settings));
  EXPECT_CALL(homedirs_, RemoveCryptohomesBasedOnPolicy())
      .WillOnce(Return(HomeDirs::CryptohomesRemovedStatus::kAll));

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, AllMounted) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(
          Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(mounted_homedirs()));

  // Allow removal of any user.
  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(true));

  // No cleanup should be performed on mounted users.
  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, OneMounted) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(
          Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1));

  auto homedirs = unmounted_homedirs();
  homedirs[2].is_mounted = true;

  EXPECT_CALL(homedirs_, GetHomeDirs()).WillRepeatedly(Return(homedirs));
  // Allow removal of any user.
  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(true));

  // No cleanup should be performed on mounted users.
  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size() - 1);
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size() - 1);
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size() - 1);
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_))
      .Times(GetTestHomedirs().size() - 1);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_))
      .Times(GetTestHomedirs().size() - 1);
  EXPECT_CALL(timestamp_manager_, RemoveUser(_))
      .Times(GetTestHomedirs().size() - 1);

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(homedirs[2].obfuscated))
      .Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(homedirs[2].obfuscated))
      .Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(homedirs[2].obfuscated))
      .Times(0);
  EXPECT_CALL(*cleanup_routines_,
              DeleteUserAndroidCache(homedirs[2].obfuscated))
      .Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(homedirs[2].obfuscated))
      .Times(0);

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, CacheCleanupStopAfterOneUser) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillOnce(Return(kFreeSpaceThresholdToTriggerCleanup - 1))
      .WillRepeatedly(Return(kTargetFreeSpaceAfterCleanup + 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_,
              DeleteUserCache(GetTestHomedirs()[0].obfuscated))
      .WillOnce(Return(true));
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, CacheCleanup) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kTargetFreeSpaceAfterCleanup + 1));

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .Times(disk_space_queries(1) - 1)
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCleanup - 1))
      .RetiresOnSaturation();

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  {
    InSequence seq;
    for (const auto& hd : GetTestHomedirs()) {
      EXPECT_CALL(*cleanup_routines_, DeleteUserCache(hd.obfuscated))
          .WillOnce(Return(true));
    }
  }

  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, GCacheCleanupStopAfterOneUser) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kTargetFreeSpaceAfterCleanup + 1));

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .Times(disk_space_queries(1) + 1)
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCleanup - 1))
      .RetiresOnSaturation();

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  // Only clean up the first user.
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_,
              DeleteUserGCache(GetTestHomedirs()[0].obfuscated))
      .WillOnce(Return(true));
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, AllCacheCleanup) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());

  {
    InSequence seq;
    for (const auto& hd : GetTestHomedirs()) {
      EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(hd.obfuscated))
          .WillOnce(Return(true));
    }

    for (const auto& hd : GetTestHomedirs()) {
      EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(hd.obfuscated))
          .WillOnce(Return(true));
    }
  }

  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, AndroidCacheStopAfterOneUser) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kTargetFreeSpaceAfterCleanup + 1));

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .Times(disk_space_queries(3) + 2)
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1))
      .RetiresOnSaturation();

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  // Only clean up the first user.
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_,
              DeleteUserAndroidCache(GetTestHomedirs()[0].obfuscated))
      .WillOnce(Return(true));
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, AndroidCache) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kTargetFreeSpaceAfterCleanup + 1));

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .Times(disk_space_queries(4))
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1))
      .RetiresOnSaturation();

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());

  {
    InSequence seq;
    for (const auto& hd : GetTestHomedirs()) {
      EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(hd.obfuscated))
          .WillOnce(Return(true));
    }
  }

  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, NoOwner) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(
          Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(homedirs_, GetOwner(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, RemoveOneProfile) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kTargetFreeSpaceAfterCleanup + 1));

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .Times(disk_space_queries(4) + 2)
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1))
      .RetiresOnSaturation();

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(homedirs_, GetOwner(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(GetTestHomedirs()[2].obfuscated),
                            Return(true)));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_,
              DeleteUserProfile(GetTestHomedirs()[0].obfuscated))
      .WillOnce(Return(true));
  EXPECT_CALL(timestamp_manager_, RemoveUser(GetTestHomedirs()[0].obfuscated));

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, KeepOwner) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(
          Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(homedirs_, GetOwner(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(GetTestHomedirs()[2].obfuscated),
                            Return(true)));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_))
      .Times(GetTestHomedirs().size());

  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);
  {
    InSequence seq;
    for (int i = 0; i < GetTestHomedirs().size(); i++) {
      // Skip owner.
      if (i == 2)
        continue;

      EXPECT_CALL(*cleanup_routines_,
                  DeleteUserProfile(GetTestHomedirs()[i].obfuscated))
          .WillOnce(Return(true));
      EXPECT_CALL(timestamp_manager_,
                  RemoveUser(GetTestHomedirs()[i].obfuscated));
    }
  }

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, KeepLatest) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(
          Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(true));
  EXPECT_CALL(homedirs_, GetOwner(_))
      .WillRepeatedly(DoAll(SetArgPointee<0>(ObfuscatedUsername("<<OWNER>>")),
                            Return(true)));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_))
      .Times(GetTestHomedirs().size());

  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);
  {
    InSequence seq;

    // Skip last user.
    for (int i = 0; i < GetTestHomedirs().size() - 1; i++) {
      EXPECT_CALL(*cleanup_routines_,
                  DeleteUserProfile(GetTestHomedirs()[i].obfuscated))
          .WillOnce(Return(true));
      EXPECT_CALL(timestamp_manager_,
                  RemoveUser(GetTestHomedirs()[i].obfuscated));
    }
  }

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, NoRepeatedCacheCleanup) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(
          Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(homedirs_, GetOwner(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  base::Time cleanup_time;
  ASSERT_TRUE(base::Time::FromUTCExploded({2020, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();

  ASSERT_TRUE(base::Time::FromUTCExploded({2021, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();

  ASSERT_TRUE(base::Time::FromUTCExploded({2022, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, RepeatNormalCleanup) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(homedirs_, GetOwner(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  base::Time cleanup_time;
  ASSERT_TRUE(base::Time::FromUTCExploded({2020, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();

  base::Time login_time;
  ASSERT_TRUE(base::Time::FromUTCExploded({2021, 4, 5, 1}, &login_time));
  EXPECT_CALL(timestamp_manager_,
              GetLastUserActivityTimestamp(GetTestHomedirs()[2].obfuscated))
      .WillRepeatedly(Return(login_time));

  EXPECT_CALL(*cleanup_routines_,
              DeleteUserCache(GetTestHomedirs()[2].obfuscated));
  EXPECT_CALL(*cleanup_routines_,
              DeleteUserGCache(GetTestHomedirs()[2].obfuscated));
  EXPECT_CALL(*cleanup_routines_,
              DeleteCacheVault(GetTestHomedirs()[2].obfuscated));

  ASSERT_TRUE(base::Time::FromUTCExploded({2022, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, RepeatAggressiveCleanup) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(0));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(homedirs_, GetOwner(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  base::Time cleanup_time;
  ASSERT_TRUE(base::Time::FromUTCExploded({2020, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();

  base::Time login_time;
  ASSERT_TRUE(base::Time::FromUTCExploded({2021, 4, 5, 1}, &login_time));
  EXPECT_CALL(timestamp_manager_,
              GetLastUserActivityTimestamp(GetTestHomedirs()[2].obfuscated))
      .WillRepeatedly(Return(login_time));

  EXPECT_CALL(*cleanup_routines_,
              DeleteUserCache(GetTestHomedirs()[2].obfuscated));
  EXPECT_CALL(*cleanup_routines_,
              DeleteUserGCache(GetTestHomedirs()[2].obfuscated));
  EXPECT_CALL(*cleanup_routines_,
              DeleteCacheVault(GetTestHomedirs()[2].obfuscated));
  EXPECT_CALL(*cleanup_routines_,
              DeleteUserAndroidCache(GetTestHomedirs()[2].obfuscated));

  ASSERT_TRUE(base::Time::FromUTCExploded({2022, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, FullAggressiveCleanupAfterNormal) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(homedirs_, GetOwner(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  base::Time cleanup_time;
  ASSERT_TRUE(base::Time::FromUTCExploded({2020, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(
          Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1));

  base::Time login_time;
  ASSERT_TRUE(base::Time::FromUTCExploded({2021, 4, 5, 1}, &login_time));
  EXPECT_CALL(timestamp_manager_,
              GetLastUserActivityTimestamp(GetTestHomedirs()[2].obfuscated))
      .WillRepeatedly(Return(login_time));

  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_))
      .Times(GetTestHomedirs().size());

  EXPECT_CALL(*cleanup_routines_,
              DeleteUserCache(GetTestHomedirs()[2].obfuscated));
  EXPECT_CALL(*cleanup_routines_,
              DeleteUserGCache(GetTestHomedirs()[2].obfuscated));
  EXPECT_CALL(*cleanup_routines_,
              DeleteCacheVault(GetTestHomedirs()[2].obfuscated));

  ASSERT_TRUE(base::Time::FromUTCExploded({2022, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, RepeatNormalCleanupAfterEarlyStop) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kTargetFreeSpaceAfterCleanup + 1));
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .Times(disk_space_queries(1) + 2)
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCleanup - 1))
      .RetiresOnSaturation();

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(homedirs_, GetOwner(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_)).Times(2);
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  base::Time cleanup_time;
  ASSERT_TRUE(base::Time::FromUTCExploded({2020, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCleanup - 1));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());

  ASSERT_TRUE(base::Time::FromUTCExploded({2022, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, RepeatAggressiveCleanupAfterEarlyStop) {
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kTargetFreeSpaceAfterCleanup + 1));
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .Times(disk_space_queries(3) + 3)
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1))
      .RetiresOnSaturation();

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(homedirs_, GetOwner(_)).WillRepeatedly(Return(false));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_))
      .Times(GetTestHomedirs().size());
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_)).Times(2);
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  base::Time cleanup_time;
  ASSERT_TRUE(base::Time::FromUTCExploded({2020, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(
          Return(kFreeSpaceThresholdToTriggerAggressiveCleanup - 1));

  EXPECT_CALL(*cleanup_routines_, DeleteUserCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserGCache(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteCacheVault(_)).Times(0);
  EXPECT_CALL(*cleanup_routines_, DeleteUserAndroidCache(_))
      .Times(GetTestHomedirs().size());

  ASSERT_TRUE(base::Time::FromUTCExploded({2022, 4, 5, 1}, &cleanup_time));
  EXPECT_CALL(platform_, GetCurrentTime).WillRepeatedly(Return(cleanup_time));

  cleanup_->FreeDiskSpace();
}

TEST_F(DiskCleanupTest, FreeDiskSpaceDuringLoginOnlyEnterprise) {
  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(false));
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot())).Times(0);

  cleanup_->FreeDiskSpaceDuringLogin(ObfuscatedUsername("testing"));
}

TEST_F(DiskCleanupTest, FreeDiskSpaceDuringLoginPolicyControl) {
  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(true));
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot())).Times(0);

  EXPECT_CALL(homedirs_, MustRunAutomaticCleanupOnLogin())
      .WillRepeatedly(Return(false));

  cleanup_->FreeDiskSpaceDuringLogin(ObfuscatedUsername("testing"));
}

TEST_F(DiskCleanupTest, FreeDiskSpaceDuringLoginCleanAll) {
  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(true));
  EXPECT_CALL(homedirs_, MustRunAutomaticCleanupOnLogin())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCriticalCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  {
    InSequence seq;

    // Skip last user.
    for (int i = 0; i < GetTestHomedirs().size(); i++) {
      EXPECT_CALL(*cleanup_routines_,
                  DeleteUserProfile(GetTestHomedirs()[i].obfuscated))
          .WillOnce(Return(true));
      EXPECT_CALL(timestamp_manager_,
                  RemoveUser(GetTestHomedirs()[i].obfuscated));
    }
  }

  cleanup_->FreeDiskSpaceDuringLogin(ObfuscatedUsername("testing"));
}

TEST_F(DiskCleanupTest, FreeDiskSpaceDuringLoginSkipLogginIn) {
  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(true));
  EXPECT_CALL(homedirs_, MustRunAutomaticCleanupOnLogin())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCriticalCleanup - 1));

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  {
    InSequence seq;

    // Skip last user.
    for (int i = 0; i < GetTestHomedirs().size(); i++) {
      if (i == 2) {
        EXPECT_CALL(*cleanup_routines_,
                    DeleteUserProfile(GetTestHomedirs()[i].obfuscated))
            .Times(0);
        continue;
      }

      EXPECT_CALL(*cleanup_routines_,
                  DeleteUserProfile(GetTestHomedirs()[i].obfuscated))
          .WillOnce(Return(true));
      EXPECT_CALL(timestamp_manager_,
                  RemoveUser(GetTestHomedirs()[i].obfuscated));
    }
  }

  cleanup_->FreeDiskSpaceDuringLogin(GetTestHomedirs()[2].obfuscated);
}

TEST_F(DiskCleanupTest, FreeDiskSpaceDuringLoginEarlyStop) {
  EXPECT_CALL(homedirs_, enterprise_owned()).WillRepeatedly(Return(true));
  EXPECT_CALL(homedirs_, MustRunAutomaticCleanupOnLogin())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(*cleanup_routines_, DeleteUserProfile(_)).Times(0);

  EXPECT_CALL(homedirs_, GetHomeDirs())
      .WillRepeatedly(Return(unmounted_homedirs()));

  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCleanup + 1));
  EXPECT_CALL(platform_, AmountOfFreeDiskSpace(ShadowRoot()))
      .Times(2)  // 1 initial query + 1 user cleanup.
      .WillRepeatedly(Return(kFreeSpaceThresholdToTriggerCriticalCleanup - 1))
      .RetiresOnSaturation();

  {
    InSequence seq;

    // Only 2 users should be cleaned up.
    for (int i = 0; i < 2; i++) {
      EXPECT_CALL(*cleanup_routines_,
                  DeleteUserProfile(GetTestHomedirs()[i].obfuscated))
          .WillOnce(Return(true));
      EXPECT_CALL(timestamp_manager_,
                  RemoveUser(GetTestHomedirs()[i].obfuscated));
    }
  }

  cleanup_->FreeDiskSpaceDuringLogin(ObfuscatedUsername("testing"));
}

}  // namespace cryptohome
