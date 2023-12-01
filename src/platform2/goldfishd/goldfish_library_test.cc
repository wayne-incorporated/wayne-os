// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "goldfishd/goldfish_library.h"

#include <string>

#include <unistd.h>

#include <base/files/file_util.h>
#include <testing/gtest/include/gtest/gtest.h>

namespace goldfishd {

namespace {

// Test if ReadOneMessage can parse |input|.
// |expected_result| is expected result.
// |expected_msg| is expected parsed message.
void ExpectReadMessage(const std::string& input,
                       bool expected_result,
                       const std::string& expected_msg) {
  int fds[2];
  int ret = pipe(fds);
  ASSERT_EQ(0, ret);
  ASSERT_TRUE(base::WriteFileDescriptor(fds[1], input));
  close(fds[1]);
  std::string got;
  EXPECT_EQ(expected_result, ReadOneMessage(fds[0], &got));
  close(fds[0]);
  if (expected_result) {
    EXPECT_EQ(expected_msg, got);
  }
}

TEST(GoldfishLibraryTest, ReadOneMessage) {
  ExpectReadMessage("0002OK", true, "OK");
  ExpectReadMessage("O", false, "");
  ExpectReadMessage("INVALID", false, "");
  ExpectReadMessage("-001OK", false, "");
  ExpectReadMessage("0400OK", false, "");
  ExpectReadMessage("0003OK", false, "");
}

}  // namespace
}  // namespace goldfishd
