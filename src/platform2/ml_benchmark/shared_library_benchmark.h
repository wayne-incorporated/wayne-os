// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_BENCHMARK_SHARED_LIBRARY_BENCHMARK_H_
#define ML_BENCHMARK_SHARED_LIBRARY_BENCHMARK_H_

#include <base/scoped_native_library.h>

#include <memory>
#include <utility>

#include "ml_benchmark/benchmark.h"
#include "ml_benchmark/benchmark_functions.h"
#include "proto/benchmark_config.pb.h"

namespace ml_benchmark {

// A benchmark class that runs shared library benchmarks
// Some benchmarks are shared libraries, mimicking how the
// corresponding ML use cases are being deployed in production
class SharedLibraryBenchmark : public Benchmark {
 public:
  explicit SharedLibraryBenchmark(
      std::unique_ptr<BenchmarkFunctions> functions_ptr);

  SharedLibraryBenchmark(const SharedLibraryBenchmark&) = delete;
  SharedLibraryBenchmark& operator=(const SharedLibraryBenchmark&) = delete;

  bool ExecuteBenchmark(const chrome::ml_benchmark::CrOSBenchmarkConfig& config,
                        chrome::ml_benchmark::BenchmarkResults* results) final;

 private:
  const std::unique_ptr<BenchmarkFunctions> functions_;
};

}  // namespace ml_benchmark

#endif  // ML_BENCHMARK_SHARED_LIBRARY_BENCHMARK_H_
