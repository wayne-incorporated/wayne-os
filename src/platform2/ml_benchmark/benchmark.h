// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_BENCHMARK_BENCHMARK_H_
#define ML_BENCHMARK_BENCHMARK_H_

#include "proto/benchmark_config.pb.h"

namespace ml_benchmark {

class Benchmark {
 public:
  // Executes an ML Benchmark
  // To implement a new ML benchmark
  // Either
  //   - Implement a class that inherits this interface
  //   - Follow the binary specifications to implement a shared library
  //     Benchmark and use the `SharedLibraryBenchmark` class
  //
  // Params:
  // `config`:  The benchmark loader will provide a benchmark configuration
  //            in the format specified by the protobuf object which should
  //            contain the benchmark-specific configurations required to
  //            execute the benchmark.
  //            The benchmark should read the relevant config and execute
  //            accordingly.
  // returns:
  // `results`: The benchmark is expected to provide the results of the
  //            benchmark in the return protobuf.
  //            If the benchmark executed but encountered an error, the
  //            error should be returned in the protobuf.
  // return:    The return value indicates if the benchmark was able to
  //            execute and return a result.
  //            A successful execution should:
  //            - return true
  //            - The status inside the result should be `ml_benchmark::OK`
  virtual bool ExecuteBenchmark(
      const chrome::ml_benchmark::CrOSBenchmarkConfig& config,
      chrome::ml_benchmark::BenchmarkResults* results) = 0;
  virtual ~Benchmark() = default;
};

}  // namespace ml_benchmark

#endif  // ML_BENCHMARK_BENCHMARK_H_
