// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "debugd/src/perf_tool.h"

namespace debugd {

TEST(PerfToolTest, GoodQuipperOptions) {
  PerfSubcommand subcommand;
  brillo::ErrorPtr error;

  EXPECT_TRUE(ValidateQuipperArguments(
      {"--duration", "2", "--", "record", "-a"}, subcommand, &error));
  EXPECT_EQ(subcommand, PERF_COMMAND_RECORD);
  EXPECT_TRUE(ValidateQuipperArguments({"--duration", "1", "--", "stat"},
                                       subcommand, &error));
  EXPECT_EQ(subcommand, PERF_COMMAND_STAT);
  EXPECT_TRUE(ValidateQuipperArguments(
      {"--duration", "2", "--", "mem", "-e", "some"}, subcommand, &error));
  EXPECT_EQ(subcommand, PERF_COMMAND_MEM);
  EXPECT_TRUE(ValidateQuipperArguments(
      {"--duration", "1", "--run_inject", "--inject_args", "-b;-f", "--",
       "record", "-e", "event"},
      subcommand, &error));
  EXPECT_EQ(subcommand, PERF_COMMAND_RECORD);
}

TEST(PerfToolTest, BlockedQuipperOptions) {
  PerfSubcommand subcommand;
  brillo::ErrorPtr error;

  EXPECT_FALSE(ValidateQuipperArguments(
      {"--duration", "2", "--output_file", "/perf.pb", "--", "record"},
      subcommand, &error));
  EXPECT_FALSE(ValidateQuipperArguments(
      {"--duration", "2", "--perf_path", "/bad/perf", "--", "stat"}, subcommand,
      &error));
}

TEST(PerfToolTest, MalformedQuipperOptions) {
  PerfSubcommand subcommand;
  brillo::ErrorPtr error;

  EXPECT_FALSE(ValidateQuipperArguments({"--duration", "--", "record"},
                                        subcommand, &error));
}

TEST(PerfToolTest, UnsupportedPerfSubcommand) {
  PerfSubcommand subcommand;
  brillo::ErrorPtr error;

  EXPECT_FALSE(ValidateQuipperArguments({"--duration", "2", "--", "list"},
                                        subcommand, &error));
  EXPECT_EQ(subcommand, PERF_COMMAND_UNSUPPORTED);
  EXPECT_FALSE(ValidateQuipperArguments(
      {"--duration", "2", "--", "inject", "-b"}, subcommand, &error));
  EXPECT_EQ(subcommand, PERF_COMMAND_UNSUPPORTED);
}

}  // namespace debugd
