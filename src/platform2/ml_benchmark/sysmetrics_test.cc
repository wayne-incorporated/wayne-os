// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/sysmetrics.h"

#include <gtest/gtest.h>

namespace ml_benchmark {

TEST(SysMetrics, Memory) {
  const int64_t original_rss = GetSwapAndRSSBytes();
  const int64_t original_size = GetVMSizeBytes();
  const int64_t original_peak_size = GetVMPeakBytes();

  EXPECT_GT(original_rss, 0);
  EXPECT_GT(original_size, 0);
  EXPECT_GE(original_peak_size, original_size);

  // Allocate 100MB more than the known peak value.
  const int hundred_mb_bytes = 1024 * 1024 * 100;
  const int mem_growth_bytes =
      (original_peak_size - original_size) + hundred_mb_bytes;
  char* allocate = new char[mem_growth_bytes];
  // Zero it out and read so the compiler doesn't optimize the variable away.
  memset(allocate, 0, mem_growth_bytes);
  EXPECT_EQ(allocate[mem_growth_bytes - 1], 0);

  const int64_t new_rss = GetSwapAndRSSBytes();
  const int64_t new_size = GetVMSizeBytes();
  const int64_t new_peak_size = GetVMPeakBytes();

  EXPECT_GE(new_rss, original_rss);
  EXPECT_GE(new_size, original_size);
  EXPECT_GE(new_peak_size, original_peak_size);

  delete[] allocate;

  // Ensure vmpeak stays high.
  EXPECT_GE(GetVMPeakBytes(), new_peak_size);
}

}  // namespace ml_benchmark
