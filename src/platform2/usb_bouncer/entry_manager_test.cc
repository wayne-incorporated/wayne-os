// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/time/time_override.h>
#include <gtest/gtest.h>

#include "usb_bouncer/entry_manager.h"
#include "usb_bouncer/entry_manager_test_util.h"
#include "usb_bouncer/util.h"

namespace usb_bouncer {

namespace {
enum class SessionState {
  kNoUser,
  kLockscreenShown,
  kUserPresent,
};

bool IsUserPresent(SessionState session_state) {
  switch (session_state) {
    case SessionState::kNoUser:
      return false;
    case SessionState::kLockscreenShown:
    case SessionState::kUserPresent:
      return true;
  }
}
}  // namespace

// Provides a callback with a static type for controlling base::Time::Now()
// during the garbage collection tests since it is undesirable for timeouts
// to be hit during the unit tests.
class TimeOverride {
 public:
  static base::Time Now() {
    now_time_ += base::Milliseconds(1);
    return now_time_;
  }

  static base::Time now_time_;
};

// static
base::Time TimeOverride::now_time_;

class EntryManagerTest : public testing::Test {
 public:
  void GarbageCollectTest(SessionState session_state) {
    // Take control of base::Time::Now() to eliminate races since the tests run
    // under extreme load.
    TimeOverride::now_time_ = base::Time::Now();
    auto time_overrides = base::subtle::ScopedTimeClockOverrides(
        &TimeOverride::Now, nullptr, nullptr);

    bool user_present = IsUserPresent(session_state);
    util_.RefreshDB(user_present /*include_user_db*/, true /*new_db*/);

    EXPECT_TRUE(util_.Get()->HandleUdev(EntryManager::UdevAction::kAdd,
                                        kDefaultDevpath));
    EXPECT_TRUE(util_.Get()->HandleUdev(EntryManager::UdevAction::kRemove,
                                        kDefaultDevpath));

    bool lockscreen_is_shown = session_state == SessionState::kLockscreenShown;
    util_.SetUserDBReadOnly(lockscreen_is_shown);

    EXPECT_EQ(util_.GarbageCollectInternal(true /*global_only*/), 0);

    EXPECT_TRUE(util_.GlobalTrashContainsEntry(kDefaultDevpath, kDefaultRule));
    if (user_present) {
      EXPECT_TRUE(util_.UserDBContainsEntry(kDefaultRule));
    }

    EXPECT_TRUE(util_.Get()->GarbageCollect());
    EXPECT_TRUE(util_.GlobalTrashContainsEntry(kDefaultDevpath, kDefaultRule));
    if (user_present) {
      EXPECT_TRUE(util_.UserDBContainsEntry(kDefaultRule));
    }

    util_.ExpireEntry(user_present, kDefaultDevpath, kDefaultRule);

    EXPECT_EQ(util_.GarbageCollectInternal(true /*global_only*/), 1);
    EXPECT_FALSE(util_.GlobalTrashContainsEntry(kDefaultDevpath, kDefaultRule));
    if (user_present) {
      EXPECT_TRUE(util_.UserDBContainsEntry(kDefaultRule));
    }

    util_.SetUserDBReadOnly(false);

    EXPECT_TRUE(util_.Get()->HandleUdev(EntryManager::UdevAction::kAdd,
                                        kDefaultDevpath));
    EXPECT_TRUE(util_.Get()->HandleUdev(EntryManager::UdevAction::kRemove,
                                        kDefaultDevpath));
    util_.ExpireEntry(user_present, kDefaultDevpath, kDefaultRule);

    util_.SetUserDBReadOnly(lockscreen_is_shown);

    EXPECT_TRUE(util_.Get()->GarbageCollect());
    EXPECT_FALSE(util_.GlobalTrashContainsEntry(kDefaultDevpath, kDefaultRule));
    if (user_present) {
      EXPECT_FALSE(util_.UserDBContainsEntry(kDefaultRule));
    }
  }

  void GenerateRulesTest(SessionState session_state) {
    bool user_present = IsUserPresent(session_state);
    util_.RefreshDB(user_present /*include_user_db*/, true /*new_db*/);

    EXPECT_FALSE(util_.Get()->GenerateRules().empty());

    EXPECT_TRUE(util_.Get()->HandleUdev(EntryManager::UdevAction::kAdd,
                                        kDefaultDevpath));

    bool lockscreen_is_shown = session_state == SessionState::kLockscreenShown;
    util_.SetUserDBReadOnly(lockscreen_is_shown);

    std::string rules = util_.Get()->GenerateRules();
    EXPECT_FALSE(rules.empty());
    EXPECT_NE(rules.find(kDefaultRule, 0), std::string::npos);
  }

  void HandleUdevTest(SessionState session_state) {
    bool user_present = IsUserPresent(session_state);
    util_.RefreshDB(user_present /*include_user_db*/, true /*new_db*/);

    bool lockscreen_is_shown = session_state == SessionState::kLockscreenShown;
    util_.SetUserDBReadOnly(lockscreen_is_shown);

    EXPECT_FALSE(util_.GlobalDBContainsEntry(kDefaultDevpath, kDefaultRule));
    EXPECT_FALSE(util_.GlobalTrashContainsEntry(kDefaultDevpath, kDefaultRule));
    if (user_present) {
      EXPECT_FALSE(util_.UserDBContainsEntry(kDefaultRule));
    }
    EXPECT_TRUE(util_.Get()->HandleUdev(EntryManager::UdevAction::kAdd,
                                        kDefaultDevpath));
    EXPECT_TRUE(util_.GlobalDBContainsEntry(kDefaultDevpath, kDefaultRule));
    EXPECT_FALSE(util_.GlobalTrashContainsEntry(kDefaultDevpath, kDefaultRule));
    if (user_present) {
      EXPECT_NE(util_.UserDBContainsEntry(kDefaultRule), lockscreen_is_shown);
    }

    EXPECT_FALSE(util_.Get()->HandleUdev(EntryManager::UdevAction::kAdd, ""));
    EXPECT_FALSE(util_.Get()->HandleUdev(EntryManager::UdevAction::kAdd,
                                         kUsbguardPolicyDir));

    EXPECT_TRUE(util_.Get()->HandleUdev(EntryManager::UdevAction::kRemove,
                                        kDefaultDevpath));
    EXPECT_FALSE(util_.GlobalDBContainsEntry(kDefaultDevpath, kDefaultRule));
    EXPECT_TRUE(util_.GlobalTrashContainsEntry(kDefaultDevpath, kDefaultRule));
    if (user_present) {
      EXPECT_NE(util_.UserDBContainsEntry(kDefaultRule), lockscreen_is_shown);
    }

    EXPECT_FALSE(
        util_.Get()->HandleUdev(EntryManager::UdevAction::kRemove, ""));
  }

 protected:
  EntryManagerTestUtil util_;
};

TEST_F(EntryManagerTest, GarbageCollect_NoUser) {
  GarbageCollectTest(SessionState::kNoUser /*session_state*/);
}

TEST_F(EntryManagerTest, GarbageCollect_LockscreenShown) {
  GarbageCollectTest(SessionState::kLockscreenShown /*session_state*/);
}

TEST_F(EntryManagerTest, GarbageCollect_UserPresent) {
  GarbageCollectTest(SessionState::kUserPresent /*session_state*/);
}

TEST_F(EntryManagerTest, GenerateRules_NoUser) {
  GenerateRulesTest(SessionState::kNoUser /*session_state*/);
}

TEST_F(EntryManagerTest, GenerateRules_LockscreenShown) {
  GenerateRulesTest(SessionState::kLockscreenShown /*session_state*/);
}

TEST_F(EntryManagerTest, GenerateRules_UserPresent) {
  GenerateRulesTest(SessionState::kUserPresent /*session_state*/);
}

TEST_F(EntryManagerTest, HandleUdev_NoUser) {
  HandleUdevTest(SessionState::kNoUser /*session_state*/);
}

TEST_F(EntryManagerTest, HandleUdev_LockscreenShown) {
  HandleUdevTest(SessionState::kLockscreenShown /*session_state*/);
}

TEST_F(EntryManagerTest, HandleUdev_UserPresent) {
  HandleUdevTest(SessionState::kUserPresent /*session_state*/);
}

TEST_F(EntryManagerTest, HandleUserLogin_NoUser) {
  util_.RefreshDB(false /*include_user_db*/, true /*new_db*/);

  EXPECT_FALSE(util_.Get()->HandleUserLogin());
}

TEST_F(EntryManagerTest, HandleUserLogin_UserPresent) {
  util_.RefreshDB(false /*include_user_db*/, true /*new_db*/);

  EXPECT_TRUE(
      util_.Get()->HandleUdev(EntryManager::UdevAction::kAdd, kDefaultDevpath));

  util_.RefreshDB(true /*include_user_db*/, false /*new_db*/);

  EXPECT_TRUE(util_.GlobalDBContainsEntry(kDefaultDevpath, kDefaultRule));
  EXPECT_FALSE(util_.UserDBContainsEntry(kDefaultRule));

  EXPECT_TRUE(util_.Get()->HandleUserLogin());
  EXPECT_TRUE(util_.UserDBContainsEntry(kDefaultRule));
}

TEST_F(EntryManagerTest, HandleUserLogin_Guest) {
  util_.RefreshDB(false /*include_user_db*/, true /*new_db*/);
  util_.SetIsGuestSession(true);

  EXPECT_TRUE(util_.Get()->HandleUserLogin());
}

}  // namespace usb_bouncer
