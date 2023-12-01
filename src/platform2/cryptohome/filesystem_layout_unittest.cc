// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/filesystem_layout.h"

#include <base/files/file_path.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "cryptohome/mock_platform.h"

namespace cryptohome {
namespace {

using ::testing::IsFalse;
using ::testing::IsTrue;
using ::testing::Return;

}  // namespace

TEST(FileSystemLayoutTest, UserSecretStashPath) {
  const ObfuscatedUsername kObfuscatedUsername("fake-user");

  EXPECT_EQ(UserSecretStashPath(kObfuscatedUsername, /*slot=*/0),
            base::FilePath("/home/.shadow/fake-user/user_secret_stash/uss.0"));
  EXPECT_EQ(
      UserSecretStashPath(kObfuscatedUsername,
                          /*slot=*/123),
      base::FilePath("/home/.shadow/fake-user/user_secret_stash/uss.123"));
}

TEST(FileSystemLayoutTest, DoesFlagFileExistWithBadNames) {
  MockPlatform platform;

  // All of these names are not valid and should fail.
  EXPECT_THAT(DoesFlagFileExist("", &platform), IsFalse());
  EXPECT_THAT(DoesFlagFileExist(".", &platform), IsFalse());
  EXPECT_THAT(DoesFlagFileExist("..", &platform), IsFalse());
  EXPECT_THAT(DoesFlagFileExist("/", &platform), IsFalse());
  EXPECT_THAT(DoesFlagFileExist("dir/name", &platform), IsFalse());
  EXPECT_THAT(DoesFlagFileExist("name/", &platform), IsFalse());
  EXPECT_THAT(DoesFlagFileExist("/abs/path", &platform), IsFalse());
}

TEST(FileSystemLayoutTest, DoesFlagFileExist) {
  MockPlatform platform;
  EXPECT_CALL(platform, FileExists(base::FilePath("/var/lib/cryptohome/abc")))
      .WillOnce(Return(true));
  EXPECT_CALL(platform, FileExists(base::FilePath("/var/lib/cryptohome/def")))
      .WillOnce(Return(false));

  EXPECT_THAT(DoesFlagFileExist("abc", &platform), IsTrue());
  EXPECT_THAT(DoesFlagFileExist("def", &platform), IsFalse());
}

}  // namespace cryptohome
