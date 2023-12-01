// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/fake_platform/real_fake_mount_mapping_redirect_factory.h"

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <gtest/gtest.h>

namespace cryptohome {

class RealFakeMountMappingRedirectFactoryTest : public ::testing::Test {};

namespace {

TEST_F(RealFakeMountMappingRedirectFactoryTest, ReturnsAChildOfTmpFs) {
  base::FilePath tmp_dir;
  base::GetTempDir(&tmp_dir);

  RealFakeMountMappingRedirectFactory factory;
  const base::FilePath dir = factory.Create();

  EXPECT_TRUE(tmp_dir.IsParent(dir));
  EXPECT_TRUE(base::PathExists(dir));

  // Cleanup.
  ASSERT_TRUE(base::DeletePathRecursively(dir));
}

}  // namespace

}  // namespace cryptohome
