// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/shadercached_helper.h"

#include <gtest/gtest.h>

namespace vm_tools::concierge {
namespace {

TEST(ShadercachedHelper, CreateShaderSharedDataParamTest) {
  ASSERT_EQ(
      "/:precompiled_gpu_cache:type=fs:cache=never:uidmap=0 65534 1,1000 333 "
      "1:gidmap=0 65534 1,1000 333 "
      "1:timeout=1:rewrite-security-xattrs=false:writeback=false",
      CreateShaderSharedDataParam(base::FilePath("/")).to_string());
}

}  // anonymous namespace
}  // namespace vm_tools::concierge
