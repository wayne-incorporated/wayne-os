// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/keymaster/keymaster_logger.h"

#include <gtest/gtest.h>

namespace arc {
namespace keymaster {

namespace {

KeymasterLogger logger;

}  // namespace

TEST(KeymasterLogger, TrimFilePath) {
  const char* input = "/full/path/to/caller.cpp, Line 42: Sample message";
  const char* output = TrimFilePathForTesting(input);
  EXPECT_STREQ(output, "caller.cpp, Line 42: Sample message");
}

TEST(KeymasterLogger, TrimFilePathWithSlash) {
  const char* input = "/full/path/to/caller.cpp, Line 42: With a / slash";
  const char* output = TrimFilePathForTesting(input);
  EXPECT_STREQ(output, "Line 42: With a / slash");
}

TEST(KeymasterLogger, TrimFilePathRandom) {
  const char* input = "Random message not following any of the assumptions";
  const char* output = TrimFilePathForTesting(input);
  EXPECT_STREQ(output, input);
}

}  // namespace keymaster
}  // namespace arc
