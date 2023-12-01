// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "installer/slow_boot_notify.h"

class SlowBootNotifyTest : public ::testing::Test {};

TEST(SlowBootNotifyTest, BothFspmNotPresentTest) {
  base::FilePath fspm_main;
  base::FilePath fspm_next;

  ASSERT_FALSE(SlowBootNotifyRequired(fspm_main, fspm_next));
}

TEST(SlowBootNotifyTest, PreFwFspmNotPresentTest) {
  base::FilePath fspm_main;
  base::FilePath fspm_next;

  EXPECT_TRUE(CreateTemporaryFile(&fspm_next));
  EXPECT_EQ(WriteFile(fspm_next, "next", 4), 4);
  ASSERT_FALSE(SlowBootNotifyRequired(fspm_main, fspm_next));
}

TEST(SlowBootNotifyTest, PostFwFspmNotPresentTest) {
  base::FilePath fspm_main;
  base::FilePath fspm_next;

  EXPECT_TRUE(CreateTemporaryFile(&fspm_main));
  EXPECT_EQ(WriteFile(fspm_main, "main", 4), 4);
  ASSERT_FALSE(SlowBootNotifyRequired(fspm_main, fspm_next));
}

TEST(SlowBootNotifyTest, FspmDiffTest) {
  base::FilePath fspm_main;
  base::FilePath fspm_next;

  EXPECT_TRUE(CreateTemporaryFile(&fspm_main));
  EXPECT_EQ(WriteFile(fspm_main, "main", 4), 4);
  EXPECT_TRUE(CreateTemporaryFile(&fspm_next));
  EXPECT_EQ(WriteFile(fspm_next, "next", 4), 4);
  ASSERT_TRUE(SlowBootNotifyRequired(fspm_main, fspm_next));
}

TEST(SlowBootNotifyTest, FspmIdenticalTest) {
  base::FilePath fspm_main;
  base::FilePath fspm_next;

  EXPECT_TRUE(CreateTemporaryFile(&fspm_main));
  EXPECT_EQ(WriteFile(fspm_main, "fspm", 4), 4);
  EXPECT_TRUE(CreateTemporaryFile(&fspm_next));
  EXPECT_EQ(WriteFile(fspm_next, "fspm", 4), 4);
  ASSERT_FALSE(SlowBootNotifyRequired(fspm_main, fspm_next));
}

TEST(SlowBootNotifyTest, FspmEmptyTest) {
  base::FilePath fspm_main;
  base::FilePath fspm_next;

  EXPECT_TRUE(CreateTemporaryFile(&fspm_main));
  EXPECT_TRUE(CreateTemporaryFile(&fspm_next));
  ASSERT_FALSE(SlowBootNotifyRequired(fspm_main, fspm_next));
}
