// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <base/files/file_path.h>
#include <gtest/gtest.h>

#include "brillo/timezone/tzif_parser.h"

namespace brillo {

namespace timezone {

class TzifParserTest : public ::testing::Test {
 public:
  TzifParserTest() {
    source_dir_ =
        base::FilePath(getenv("SRC")).Append("brillo").Append("timezone");
  }

 protected:
  base::FilePath source_dir_;
};

TEST_F(TzifParserTest, EST) {
  auto posix_result = GetPosixTimezone(source_dir_.Append("EST_test.tzif"));
  EXPECT_EQ(posix_result, "EST5");
}

TEST_F(TzifParserTest, TzifVersionTwo) {
  auto posix_result =
      GetPosixTimezone(source_dir_.Append("Indian_Christmas_test.tzif"));
  EXPECT_EQ(posix_result, "<+07>-7");
}

TEST_F(TzifParserTest, TzifVersionThree) {
  auto posix_result =
      GetPosixTimezone(source_dir_.Append("Pacific_Fiji_test.tzif"));
  EXPECT_EQ(posix_result, "<+12>-12<+13>,M11.1.0,M1.2.2/123");
}

}  // namespace timezone

}  // namespace brillo
