// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/cellular/cellular_helpers.h"

#include <gtest/gtest.h>

using testing::Test;

namespace shill {

TEST(CellularHelpersTest, GetStringmapValue) {
  Stringmap string_map;
  EXPECT_STREQ(GetStringmapValue(string_map, "test_key").c_str(), "");
  EXPECT_EQ(string_map.size(), 0);

  EXPECT_STREQ(GetStringmapValue(string_map, "test_key", "default").c_str(),
               "default");
  EXPECT_EQ(string_map.size(), 0);

  string_map["key1"] = "val1";
  EXPECT_STREQ(GetStringmapValue(string_map, "key1").c_str(), "val1");
  EXPECT_STREQ(GetStringmapValue(string_map, "key1", "default").c_str(),
               "val1");
  EXPECT_EQ(string_map.size(), 1);
}

}  // namespace shill
