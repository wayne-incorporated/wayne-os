// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_BENCHMARK_SYSMETRICS_H_
#define ML_BENCHMARK_SYSMETRICS_H_

#include <cstdint>

namespace ml_benchmark {

// Reads the 'VmSize:' value from /proc/self/status
// returns:            The virtual memory size of the current process in bytes.
int64_t GetVMSizeBytes();

// Reads the 'VmPeak:' value from /proc/self/status
// returns:            The highest virtual memory size of the current process.
int64_t GetVMPeakBytes();

// Reads the 'VmRSS' added to 'VmSwap' value from /proc/self/status
// returns:            The RSS and Swap usage of the current process.
int64_t GetSwapAndRSSBytes();

}  // namespace ml_benchmark

#endif  // ML_BENCHMARK_SYSMETRICS_H_
