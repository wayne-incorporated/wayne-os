// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Unit tests for UsersOldestActivityTimestampCache.

#include "cryptohome/cleanup/user_oldest_activity_timestamp_manager.h"

#include <base/check.h>
#include <base/logging.h>
#include <gtest/gtest.h>

#include "cryptohome/filesystem_layout.h"
#include "cryptohome/mock_platform.h"

namespace {
const base::Time::Exploded feb1st2011_exploded = {2011, 2, 2, 1};
const base::Time::Exploded mar1st2011_exploded = {2011, 3, 2, 1};
const base::Time::Exploded apr1st2011_exploded = {2011, 4, 2, 1};
}  // namespace

namespace cryptohome {

using testing::Eq;
using testing::NiceMock;
using testing::Return;

// TODO(b/205759690, dlunev): can be removed after a stepping stone release.
TEST(UserOldestActivityTimestampManager, Legacy) {
  const ObfuscatedUsername kUserB("b");
  const ObfuscatedUsername kUserC("c");

  base::Time time_feb1;
  CHECK(base::Time::FromUTCExploded(feb1st2011_exploded, &time_feb1));
  base::Time time_mar1;
  CHECK(base::Time::FromUTCExploded(mar1st2011_exploded, &time_mar1));
  base::Time time_apr1;
  CHECK(base::Time::FromUTCExploded(apr1st2011_exploded, &time_apr1));

  NiceMock<MockPlatform> mock_platform;
  EXPECT_CALL(mock_platform, GetCurrentTime()).WillOnce(Return(time_mar1));

  ASSERT_TRUE(mock_platform.CreateDirectory(
      UserActivityTimestampPath(kUserB).DirName()));
  ASSERT_TRUE(mock_platform.CreateDirectory(
      UserActivityTimestampPath(kUserC).DirName()));

  {
    UserOldestActivityTimestampManager manager(&mock_platform);

    manager.LoadTimestamp(kUserB);
    manager.LoadTimestamp(kUserC);

    // No values yet.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(base::Time()));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(base::Time()));

    manager.UpdateTimestamp(kUserB, base::TimeDelta());

    // One set value.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(time_mar1));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(base::Time()));
  }

  {
    UserOldestActivityTimestampManager manager(&mock_platform);

    manager.LoadTimestampWithLegacy(kUserB, time_feb1);
    manager.LoadTimestampWithLegacy(kUserC, time_feb1);

    // 'b' has a newer value than legacy and thus should ignroe the legacy.
    // 'c' has no value and should get legacy.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(time_mar1));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(time_feb1));
  }

  {
    UserOldestActivityTimestampManager manager(&mock_platform);

    manager.LoadTimestamp(kUserB);
    manager.LoadTimestamp(kUserC);

    // Test the values are preserved.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(time_mar1));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(time_feb1));
  }

  {
    UserOldestActivityTimestampManager manager(&mock_platform);

    manager.LoadTimestampWithLegacy(kUserB, time_apr1);
    manager.LoadTimestampWithLegacy(kUserC, time_apr1);

    // Both 'b' and 'c' are older than legacy, thus should take it.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(time_apr1));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(time_apr1));
  }

  {
    UserOldestActivityTimestampManager manager(&mock_platform);

    manager.LoadTimestamp(kUserB);
    manager.LoadTimestamp(kUserC);

    // Test the values are preserved.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(time_apr1));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(time_apr1));
  }
}

TEST(UserOldestActivityTimestampManager, Regular) {
  const ObfuscatedUsername kUserB("b");
  const ObfuscatedUsername kUserC("c");

  base::Time time_feb1;
  CHECK(base::Time::FromUTCExploded(feb1st2011_exploded, &time_feb1));
  base::Time time_mar1;
  CHECK(base::Time::FromUTCExploded(mar1st2011_exploded, &time_mar1));
  base::Time time_apr1;
  CHECK(base::Time::FromUTCExploded(apr1st2011_exploded, &time_apr1));

  NiceMock<MockPlatform> mock_platform;
  EXPECT_CALL(mock_platform, GetCurrentTime())
      .WillOnce(Return(time_feb1))
      .WillOnce(Return(time_mar1))
      .WillOnce(Return(time_apr1));

  ASSERT_TRUE(mock_platform.CreateDirectory(
      UserActivityTimestampPath(kUserB).DirName()));
  ASSERT_TRUE(mock_platform.CreateDirectory(
      UserActivityTimestampPath(kUserC).DirName()));

  {
    UserOldestActivityTimestampManager manager(&mock_platform);

    manager.LoadTimestamp(kUserB);
    manager.LoadTimestamp(kUserC);

    // No values yet.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(base::Time()));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(base::Time()));
  }

  {
    UserOldestActivityTimestampManager manager(&mock_platform);

    manager.UpdateTimestamp(kUserB, base::TimeDelta());
    manager.UpdateTimestamp(kUserC, base::TimeDelta());

    // Values are set.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(time_feb1));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(time_mar1));
  }

  {
    UserOldestActivityTimestampManager manager(&mock_platform);

    manager.LoadTimestamp(kUserB);
    manager.LoadTimestamp(kUserC);

    // Test the values are preserved.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(time_feb1));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(time_mar1));

    manager.UpdateTimestamp(kUserB, base::TimeDelta());

    // One value is updated.
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserB), Eq(time_apr1));
    EXPECT_THAT(manager.GetLastUserActivityTimestamp(kUserC), Eq(time_mar1));
  }
}

}  // namespace cryptohome
