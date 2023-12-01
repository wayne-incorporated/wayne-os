// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "virtual_file_provider/service.h"

namespace virtual_file_provider {

TEST(ServiceTest, IsValidVirtualFileId) {
  // A valid GUID.
  EXPECT_TRUE(
      Service::IsValidVirtualFileId("7ae6da59-36d0-4026-b5b4-17714ec41d83"));

  // Should reject paths with "..".
  EXPECT_FALSE(Service::IsValidVirtualFileId(".."));
  EXPECT_FALSE(Service::IsValidVirtualFileId("../foo"));
}

}  // namespace virtual_file_provider
