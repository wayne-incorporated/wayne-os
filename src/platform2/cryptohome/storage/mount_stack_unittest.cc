// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/storage/mount_stack.h"

#include <base/files/file_path.h>
#include <gtest/gtest.h>

using base::FilePath;

namespace cryptohome {

TEST(MountStackTest, Correctness) {
  const base::FilePath kSrc1("/foo_src");
  const base::FilePath kDest1("/foo_dest");
  const base::FilePath kSrc2("/bar_src");
  const base::FilePath kDest2("/bar_dest");

  MountStack stack;
  stack.Push(kSrc1, kDest1);
  stack.Push(kSrc2, kDest2);

  EXPECT_TRUE(stack.ContainsDest(kDest1));
  EXPECT_TRUE(stack.ContainsDest(kDest2));
  EXPECT_FALSE(stack.ContainsDest(kSrc1));
  EXPECT_FALSE(stack.ContainsDest(base::FilePath("/bogus")));

  base::FilePath src_result, dest_result;
  EXPECT_TRUE(stack.Pop(&src_result, &dest_result));
  EXPECT_EQ(kSrc2, src_result);
  EXPECT_EQ(kDest2, dest_result);

  EXPECT_TRUE(stack.Pop(&src_result, &dest_result));
  EXPECT_EQ(kSrc1, src_result);
  EXPECT_EQ(kDest1, dest_result);

  EXPECT_FALSE(stack.Pop(&src_result, &dest_result));
}

}  // namespace cryptohome
