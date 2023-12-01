// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <map>
#include <string>

#include <gtest/gtest.h>

#include "mems_setup/delegate_impl.h"

namespace mems_setup {

namespace {

TEST(VpdLoader, WellFormedEntries) {
  std::map<std::string, std::string> entries;
  std::string data = R"foo("key1"="value1"
"key2"="value2"
  )foo";
  ASSERT_TRUE(LoadVpdFromString(data, &entries));
  ASSERT_EQ(2, entries.size());
  ASSERT_EQ("value1", entries.at("key1"));
  ASSERT_EQ("value2", entries.at("key2"));
}

TEST(VpdLoader, NoTrailingNewline) {
  std::map<std::string, std::string> entries;
  std::string data = R"foo("key1"="value1"
"key2"="value2")foo";
  ASSERT_TRUE(LoadVpdFromString(data, &entries));
  ASSERT_EQ(2, entries.size());
  ASSERT_EQ("value1", entries.at("key1"));
  ASSERT_EQ("value2", entries.at("key2"));
}

}  // namespace

}  // namespace mems_setup
