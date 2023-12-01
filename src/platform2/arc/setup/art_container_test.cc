// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/setup/art_container.h"

#include <unistd.h>

#include <limits>

#include <gtest/gtest.h>

namespace arc {
namespace {

// Tests that ChooseRelocationOffsetDelta() returns a reasonable value when
// seed is non-zero.
TEST(ArtContainer, TestChooseRelocationOffsetDelta) {
  const int32_t page_size = getpagesize();
  const int32_t min = page_size;
  const int32_t max = min * 3;
  const int32_t test_range = max * 2;

  for (uint64_t seed = 0; seed < test_range; ++seed) {
    const int32_t offset =
        ArtContainer::ChooseRelocationOffsetDeltaForTesting(min, max, seed);
    EXPECT_LE(min, offset) << seed;
    EXPECT_GE(max, offset) << seed;
    EXPECT_EQ(0, offset % page_size) << seed;
  }

  constexpr uint64_t kUint64Max = std::numeric_limits<uint64_t>::max();
  for (uint64_t seed = kUint64Max; seed >= kUint64Max - test_range; --seed) {
    const int32_t offset =
        ArtContainer::ChooseRelocationOffsetDeltaForTesting(min, max, seed);
    EXPECT_LE(min, offset) << seed;
    EXPECT_GE(max, offset) << seed;
    EXPECT_EQ(0, offset % page_size) << seed;
  }
}

// Does the same without a seed.
TEST(ArtContainer, TestChooseRelocationOffsetDelta_Random) {
  const int32_t page_size = getpagesize();
  const int32_t min = page_size;
  const int32_t max = min * 3;

  constexpr int32_t kNumLoop = 1024;
  for (uint64_t count = 0; count < kNumLoop; ++count) {
    const int32_t offset =
        ArtContainer::ChooseRelocationOffsetDeltaForTesting(min, max, 0);
    EXPECT_LE(min, offset) << offset;
    EXPECT_GE(max, offset) << offset;
    EXPECT_EQ(0, offset % page_size) << offset;
  }
}

}  // namespace
}  // namespace arc
