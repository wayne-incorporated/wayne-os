// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/shared_library_benchmark.h"

#include <base/check.h>
#include <base/logging.h>

#include <memory>
#include <string>

namespace ml_benchmark {

SharedLibraryBenchmark::SharedLibraryBenchmark(
    std::unique_ptr<BenchmarkFunctions> functions)
    : functions_(std::move(functions)) {
  CHECK(functions_ != nullptr);
}

bool SharedLibraryBenchmark::ExecuteBenchmark(
    const chrome::ml_benchmark::CrOSBenchmarkConfig& config,
    chrome::ml_benchmark::BenchmarkResults* results) {
  std::string config_bytes;
  if (!config.SerializeToString(&config_bytes)) {
    LOG(ERROR) << "Unable to serialize configuration protobuf";
    return false;
  }

  void* results_buffer = nullptr;
  int32_t results_size = 0;
  auto ret =
      functions_->BenchmarkFunction(config_bytes.c_str(), config_bytes.size(),
                                    &results_buffer, &results_size);

  auto deleter = [this](void* memory) {
    functions_->FreeBenchmarkResults(memory);
  };
  std::unique_ptr<void, decltype(deleter)> managed_results(results_buffer,
                                                           deleter);

  if (results_buffer == nullptr || results_size == 0) {
    LOG(ERROR) << "Cannot parse the results from the test driver: "
               << "Driver did not return a buffer or a correct size";
    return false;
  }

  if (!results->ParseFromArray(results_buffer, results_size)) {
    LOG(ERROR) << "Cannot parse the results from the test driver: "
               << "Driver did not return a valid result";
    return false;
  }

  if (ret != results->status()) {
    LOG(ERROR) << "Status mismatch: return code " << ret << " vs proto status "
               << results->status();
    return false;
  }

  return true;
}

}  // namespace ml_benchmark
