// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chromeos/ui/util.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

namespace chromeos {
namespace ui {
namespace util {

TEST(UtilTest, EnsureDirectoryExists) {
  base::ScopedTempDir temp_dir;
  ASSERT_TRUE(temp_dir.CreateUniqueTempDir());

  // Verify that a new directory is created.
  base::FilePath path_a = temp_dir.GetPath().Append("a");
  EXPECT_TRUE(EnsureDirectoryExists(path_a, getuid(), getgid(), 0755));
  EXPECT_TRUE(base::DirectoryExists(path_a));

  // Verify that it doesn't fail even if the directory already exists.
  EXPECT_TRUE(EnsureDirectoryExists(path_a, getuid(), getgid(), 0755));
  EXPECT_TRUE(base::DirectoryExists(path_a));

  // Verify that it doesn't fail even if a file already exists at the path.
  base::FilePath path_b = temp_dir.GetPath().Append("b");
  EXPECT_EQ(0, base::WriteFile(path_b, nullptr, 0));
  EXPECT_TRUE(EnsureDirectoryExists(path_b, getuid(), getgid(), 0755));
  EXPECT_TRUE(base::DirectoryExists(path_b));
}

}  // namespace util
}  // namespace ui
}  // namespace chromeos
