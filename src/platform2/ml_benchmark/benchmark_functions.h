// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_BENCHMARK_BENCHMARK_FUNCTIONS_H_
#define ML_BENCHMARK_BENCHMARK_FUNCTIONS_H_

namespace ml_benchmark {

// This class models the shared library interface specified in the
// ML Benchmark Suite design documents.
// Each function in the interface corresponds to a function that each
// shared library benchmark driver must implement.
// Refer to the design document for more details on the shared library API
// contracts.
class BenchmarkFunctions {
 public:
  virtual ~BenchmarkFunctions() = default;

  // Executes the benchmark
  // Params
  // `config_bytes`:      A buffer which contains the serialized configuration
  //                      protobuf.
  //                      Refer to `benchmark.h` for more details on the config
  //                      format.
  // `config_bytes_size`: The length of the `config_bytes` buffer.
  // returns:             Indicates how the benchmark executed.
  //                      Return values should be identical to the `status`
  //                      field in the return results.
  //                      0 indicates the execution was successful.
  // `results_bytes`:     The benchmark is expected to return a pointer to a
  //                      buffer which contains the serialized results protobuf.
  //                      The benchmark might not return a value if an error
  //                      occurs.
  // `results_bytes_size`:The length of the results_bytes array.
  virtual int32_t BenchmarkFunction(const void* config_bytes,
                                    int32_t config_bytes_size,
                                    void** results_bytes,
                                    int32_t* results_bytes_size) = 0;

  // Frees the benchmark results allocated by BenchmarkFunction.
  // If nullptr was passed in, the free function will do nothing.
  // Params
  // `memory`: The same results_bytes pointer obtained from BenchmarkFunction.
  virtual void FreeBenchmarkResults(void* memory) = 0;
};

}  // namespace ml_benchmark

#endif  // ML_BENCHMARK_BENCHMARK_FUNCTIONS_H_
