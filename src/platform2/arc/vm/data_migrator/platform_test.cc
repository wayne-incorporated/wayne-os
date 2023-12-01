// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/data_migrator/platform.h"

#include <base/files/file_path.h>
#include <gtest/gtest.h>

namespace arc::data_migrator {

TEST(ArcVmDataMigratorPlatformTest, ReferencesParent) {
  const base::FilePath mount_point_path("/tmp/arcvm-data-migration-mount");
  EXPECT_FALSE(ReferencesParent(mount_point_path));
  EXPECT_TRUE(ReferencesParent(mount_point_path.Append("..")));
  EXPECT_TRUE(ReferencesParent(mount_point_path.Append("..").Append("test")));
  EXPECT_FALSE(ReferencesParent(mount_point_path.Append("...")));
  EXPECT_FALSE(ReferencesParent(mount_point_path.Append(" ..")));
  EXPECT_FALSE(ReferencesParent(mount_point_path.Append(".. ")));
}

}  // namespace arc::data_migrator
