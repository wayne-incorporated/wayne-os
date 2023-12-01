// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "diagnostics/cros_minidiag/utils.h"

namespace cros_minidiag {

namespace {

constexpr const char kMockFileName[] = "last-line";
constexpr const char kMockLine[] = "mock";

class GetPrevElogLastLineTest : public testing::Test {
 protected:
  void SetUp() override {
    CHECK(scoped_temp_dir_.CreateUniqueTempDir());
    path_ = scoped_temp_dir_.GetPath().Append(kMockFileName);
    ret_line_.clear();
  }

  base::ScopedTempDir scoped_temp_dir_;
  base::FilePath path_;
  std::string ret_line_ = "";
};

TEST_F(GetPrevElogLastLineTest, BaseLastLine) {
  EXPECT_EQ(base::WriteFile(path_, kMockLine), true);
  EXPECT_EQ(GetPrevElogLastLine(path_, ret_line_), true);
  EXPECT_EQ(ret_line_, kMockLine);
}

TEST_F(GetPrevElogLastLineTest, LastLineTrimTail) {
  std::string line_tail_space(kMockLine);
  line_tail_space.append("   \n");
  EXPECT_EQ(base::WriteFile(path_, line_tail_space), true);
  EXPECT_EQ(GetPrevElogLastLine(path_, ret_line_), true);
  EXPECT_EQ(ret_line_, kMockLine);
}

TEST_F(GetPrevElogLastLineTest, LastLineNoTrimLeadSpace) {
  std::string line_lead_space("   ");
  line_lead_space.append(kMockLine);
  EXPECT_EQ(base::WriteFile(path_, line_lead_space), true);
  EXPECT_EQ(GetPrevElogLastLine(path_, ret_line_), true);
  EXPECT_EQ(ret_line_, line_lead_space);
}

TEST_F(GetPrevElogLastLineTest, BadFileName) {
  const auto bad_path = scoped_temp_dir_.GetPath().Append("bad-path");
  EXPECT_EQ(GetPrevElogLastLine(bad_path, ret_line_), false);
  EXPECT_EQ(ret_line_, "");
}

TEST_F(GetPrevElogLastLineTest, BadFileSize) {
  std::string long_string = "";
  while (long_string.length() <= cros_minidiag::kMaxFileSize) {
    long_string.append(kMockLine);
  }
  EXPECT_EQ(base::WriteFile(path_, long_string), true);
  EXPECT_EQ(GetPrevElogLastLine(path_, ret_line_), false);
  EXPECT_EQ(ret_line_, "");
}

}  // namespace
}  // namespace cros_minidiag
