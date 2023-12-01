// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vm_tools/concierge/mglru_util.h"

#include <gtest/gtest.h>

namespace vm_tools::concierge::mglru {
namespace {

void ASSERT_STATS_EQUAL(const MglruStats& lhs, const MglruStats& rhs) {
  ASSERT_EQ(StatsToString(lhs), StatsToString(rhs));
}

TEST(MglruUtilTest, TestEmpty) {
  std::optional<MglruStats> stats = ParseStatsFromString("");
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestWrongTokenCg) {
  const std::string input =
      R"(Pmemcg     0
 node     0
        695      40523      18334        4175
)";

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestMissingIdCg) {
  const std::string input =
      R"(memcg
 node     0
        695      40523      18334        4175
)";

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestWrongTokenNode) {
  const std::string input =
      R"(memcg     0
 Pnode     0
        695      40523      18334        4175
)";

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestMissingIdNode) {
  const std::string input =
      R"(memcg     0
 node
        695      40523      18334        4175
)";

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestMissingCgHeader) {
  const std::string input =
      R"(node     0
        695      40523      18334        4175
)";

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestMissingNodeHeader) {
  const std::string input =
      R"(memcg     0
        695      40523      18334        4175
)";

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestMissingGeneration) {
  const std::string input =
      R"(memcg     0
 node     0
)";

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestTooBigGeneration) {
  const std::string input =
      R"(memcg     0
 node     0
        695      40523      18334        4175 55
        695      40523      18334        4175
)";

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestTooSmallGeneration) {
  const std::string input =
      R"(memcg     0
 node     0
        695      40523      18334
        695      40523      18334        4175
)";

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_FALSE(stats);
}

TEST(MglruUtilTest, TestSimple) {
  const std::string input =
      R"(memcg     1
 node     2
        3      4      5        6
)";

  const MglruStats expected_stats = {.cgs = {{// CG 0
                                              .id = 1,
                                              .nodes = {{// Node 0
                                                         .id = 2,
                                                         .generations = {
                                                             {3, 4, 5, 6},
                                                         }}}}}};

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_TRUE(stats);
  ASSERT_STATS_EQUAL(expected_stats, *stats);
}

TEST(MglruUtilTest, TestMultiple) {
  const std::string input =
      R"(memcg     0
 node     0
        695      40523      18334        4175
        696      35101      35592       22242
        697      10961      32552       12081
        698       3419      21460        4438
 node     1
        695      40523      18334        4175
        696      35101      35592       22242
        697      10961      32552       12081
        698       3419      21460        4438
memcg     1
 node     0
        695      40523      18334        4175
        696      35101      35592       22242
        697      10961      32552       12081
        698       3419      21460        4438
)";

  const MglruStats expected_stats = {
      .cgs = {{// CG 0
               .id = 0,
               .nodes = {{// Node 0
                          .id = 0,
                          .generations = {{695, 40523, 18334, 4175},
                                          {696, 35101, 35592, 22242},
                                          {697, 10961, 32552, 12081},
                                          {698, 3419, 21460, 4438}}},
                         {// Node 1
                          .id = 1,
                          .generations = {{695, 40523, 18334, 4175},
                                          {696, 35101, 35592, 22242},
                                          {697, 10961, 32552, 12081},
                                          {698, 3419, 21460, 4438}}}}},
              {// CG 1
               .id = 1,
               .nodes = {{// Node 0
                          .id = 0,
                          .generations = {{695, 40523, 18334, 4175},
                                          {696, 35101, 35592, 22242},
                                          {697, 10961, 32552, 12081},
                                          {698, 3419, 21460, 4438}}}}}}};

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_TRUE(stats);
  ASSERT_STATS_EQUAL(expected_stats, *stats);
}

TEST(MglruUtilTest, TestMultipleCrostini) {
  const std::string input =
      R"(memcg     1 /
  node     0
           0       1177          0         822
           1       1177          7           0
           2       1177          0           0
           3       1177       1171        5125
)";

  const MglruStats expected_stats = {
      .cgs = {{// CG 0
               .id = 1,
               .nodes = {{// Node 0
                          .id = 0,
                          .generations = {{0, 1177, 0, 822},
                                          {1, 1177, 7, 0},
                                          {2, 1177, 0, 0},
                                          {3, 1177, 1171, 5125}}}}}}};

  std::optional<MglruStats> stats = ParseStatsFromString(input);
  ASSERT_TRUE(stats);
  ASSERT_STATS_EQUAL(expected_stats, *stats);
}

}  // namespace
}  // namespace vm_tools::concierge::mglru
