// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include <string>

#include "vm_tools/maitred/init.h"

namespace vm_tools {
namespace maitred {

TEST(ImplTest, ParseHostnameParsesTypicalCase) {
  std::string etc_hostname("Chromebook\n");
  EXPECT_EQ(ParseHostname(etc_hostname), "Chromebook");
}

TEST(ImplTest, ParseHostnameIgnoresComments) {
  std::string etc_hostname("# this is a comment\nChromebook\n");
  EXPECT_EQ(ParseHostname(etc_hostname), "Chromebook");
}

TEST(ImplTest, ParseHostnameHandlesEmptyCase) {
  std::string etc_hostname;
  EXPECT_EQ(ParseHostname(etc_hostname), "");
}

TEST(ImplTest, ParseHostnameIgnoresMultipleNames) {
  std::string etc_hostname("one\ntwo\n");
  EXPECT_EQ(ParseHostname(etc_hostname), "one");
}

}  // namespace maitred
}  // namespace vm_tools
