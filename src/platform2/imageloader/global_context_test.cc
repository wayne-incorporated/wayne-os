// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "imageloader/global_context.h"

namespace imageloader {

TEST(GlobalContextTest, SetCurrent) {
  GlobalContext g_ctx_1;
  g_ctx_1.SetAsCurrent();
  EXPECT_EQ(&g_ctx_1, GlobalContext::Current());

  // To make sure the previous value was overriden.
  GlobalContext g_ctx_2;
  g_ctx_2.SetAsCurrent();
  EXPECT_EQ(&g_ctx_2, GlobalContext::Current());
}

}  // namespace imageloader
