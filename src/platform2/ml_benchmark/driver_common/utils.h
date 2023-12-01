// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_BENCHMARK_DRIVER_COMMON_UTILS_H_
#define ML_BENCHMARK_DRIVER_COMMON_UTILS_H_

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

#include <base/check.h>

#include "proto/benchmark_config.pb.h"

namespace chrome {
namespace ml_benchmark {

// The percentiles expected to be reported in percentile_latencies_in_us in
// BenchmarkResults. May also be used for custom metrics, such as CPU time.
constexpr int32_t kLatencyPercentiles[] = {50, 90, 95, 99};

// Serializes a BenchmarkResults into a buffer as expected by benchmark_start.
// Allocates a buffer, whose location and size are returned in `results_data`
// and `results_size`, and must be freed using FreeSerializedResults.
int32_t SerializeResults(const BenchmarkResults& results,
                         void** results_data,
                         int32_t* results_size);

// Generates a BenchmarkResults proto containing an error code and message,
// and directly serializes it into a buffer as expected by benchmark_start.
// Allocates a buffer, whose location and size are returned in `results_data`
// and `results_size`, and must be freed using FreeSerializedResults.
int32_t SerializeError(const std::string& error_message,
                       BenchmarkReturnStatus status,
                       void** results_data,
                       int32_t* results_size);

// Frees a buffer returned by SerializeResults or SerializeError, as needed by
// free_benchmark_results. Does nothing if called with nullptr.
void FreeSerializedResults(void* results_data);

// Taken from chromium source cc/base/rolling_time_delta_history.cc
// http://shortn/_mIhMWhPIUF and simplified since we're using a vector
// and can index directly.
// `samples` should be sorted before calling.
// Returns the smallest sample that is greater than or equal to the specified
// percent of samples. If there aren't any samples, returns 0.
template <typename T>
T ComputePercentile(const std::vector<T>& samples, double percent) {
  if (samples.size() == 0)
    return T(0);

  CHECK(std::is_sorted(samples.begin(), samples.end()));

  double fraction = percent / 100.0;

  if (fraction <= 0.0)
    return *(samples.begin());
  if (fraction >= 1.0)
    return *(samples.rbegin());

  size_t index = static_cast<size_t>(std::ceil(fraction * samples.size())) - 1;
  return samples[index];
}

// Fills in percentile_latencies_in_us in `results` with the percentiles
// expected by the framework, as listed in kLatencyPercentiles.
// The percentiles are extracted from `latencies`, which must be given in
// microseconds, and must be sorted before calling.
template <typename T>
void SetPercentileLatencies(BenchmarkResults& results,
                            const std::vector<T>& latencies) {
  auto& percentile_latencies = *results.mutable_percentile_latencies_in_us();
  for (const int32_t percentile : kLatencyPercentiles) {
    percentile_latencies[percentile] = ComputePercentile(latencies, percentile);
  }
}

}  // namespace ml_benchmark
}  // namespace chrome

#endif  // ML_BENCHMARK_DRIVER_COMMON_UTILS_H_
