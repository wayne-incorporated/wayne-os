// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/tagged_device.h"

#include <base/files/file_path.h>

#include <gtest/gtest.h>

namespace power_manager::system {

TEST(TaggedDeviceTest, HasTag) {
  TaggedDevice tagged_device("/sys/devices/a", base::FilePath("/sys/devices/a"),
                             "foo bar");
  EXPECT_TRUE(tagged_device.HasTag("foo"));
  EXPECT_TRUE(tagged_device.HasTag("bar"));
  EXPECT_FALSE(tagged_device.HasTag("baz"));
}

}  // namespace power_manager::system
