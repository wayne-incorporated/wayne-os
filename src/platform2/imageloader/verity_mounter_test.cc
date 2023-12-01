// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "imageloader/verity_mounter_impl.h"

namespace imageloader {

TEST(VerityMounterTest, MapperParametersToLoop) {
  // Test valid case.
  int32_t loop = -1;
  EXPECT_TRUE(
      MapperParametersToLoop("0 7:6 7:6 4096 4096 3089 3089 sha256 "
                             "eef4aa5dc50d181b7f6...",
                             &loop));
  EXPECT_EQ(loop, 6);

  // Make sure notable edge cases are handled correctly.
  EXPECT_FALSE(MapperParametersToLoop("", &loop));
  EXPECT_FALSE(MapperParametersToLoop("0 7 6 7:6", &loop));
  EXPECT_FALSE(MapperParametersToLoop("0 7:a 7:6", &loop));
}

TEST(VerityMounterTest, IsAncestor) {
  // Test valid case.
  const base::FilePath ancestor("/dev/mapper/");
  const base::FilePath descendant("/dev/mapper/0123456789ABCDEF");
  EXPECT_TRUE(IsAncestor(ancestor, descendant));

  // Test reverse case.
  EXPECT_FALSE(IsAncestor(descendant, ancestor));

  // Test same path case.
  EXPECT_FALSE(IsAncestor(ancestor, ancestor));
}

}  // namespace imageloader
