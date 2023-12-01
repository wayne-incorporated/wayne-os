// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_BENCHMARK_SHARED_LIBRARY_BENCHMARK_FUNCTIONS_H_
#define ML_BENCHMARK_SHARED_LIBRARY_BENCHMARK_FUNCTIONS_H_

#include <base/files/file_path.h>
#include <base/scoped_native_library.h>

#include "ml_benchmark/benchmark_functions.h"

namespace ml_benchmark {

typedef int32_t (*benchmark_function)(const void* config_bytes,
                                      int32_t config_bytes_size,
                                      void** results_bytes,
                                      int32_t* results_bytes_size);

typedef void (*free_benchmark_results_function)(void* results_bytes);

class SharedLibraryBenchmarkFunctions : public BenchmarkFunctions {
 public:
  explicit SharedLibraryBenchmarkFunctions(const base::FilePath& path);
  SharedLibraryBenchmarkFunctions(const SharedLibraryBenchmarkFunctions&) =
      delete;
  SharedLibraryBenchmarkFunctions& operator=(
      const SharedLibraryBenchmarkFunctions&) = delete;

  bool valid() const { return valid_; }

  int32_t BenchmarkFunction(const void* config_bytes,
                            int32_t config_bytes_size,
                            void** results_bytes,
                            int32_t* results_bytes_size) final;
  void FreeBenchmarkResults(void* results_bytes) final;

 private:
  base::ScopedNativeLibrary library_;
  benchmark_function benchmark_function_;
  free_benchmark_results_function free_benchmark_results_function_;
  bool valid_ = false;
};

}  // namespace ml_benchmark

#endif  // ML_BENCHMARK_SHARED_LIBRARY_BENCHMARK_FUNCTIONS_H_
