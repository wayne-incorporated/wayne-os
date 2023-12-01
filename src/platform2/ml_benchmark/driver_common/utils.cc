// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/driver_common/utils.h"

#include <cstdint>
#include <string>

#include "proto/benchmark_config.pb.h"

namespace chrome {
namespace ml_benchmark {

int32_t SerializeResults(const BenchmarkResults& results,
                         void** results_data,
                         int32_t* results_size) {
  CHECK(results_data);
  CHECK(results_size);

  const std::string result_pb = results.SerializeAsString();
  CHECK(!result_pb.empty());
  const int32_t size = result_pb.size();
  char* const data = new char[size];
  result_pb.copy(data, size);
  *results_data = data;
  *results_size = size;
  return results.status();
}

int32_t SerializeError(const std::string& error_message,
                       BenchmarkReturnStatus status,
                       void** results_data,
                       int32_t* results_size) {
  chrome::ml_benchmark::BenchmarkResults results;
  results.set_status(status);
  results.set_results_message(error_message);
  return SerializeResults(results, results_data, results_size);
}

void FreeSerializedResults(void* results_data) {
  delete[] static_cast<char*>(results_data);
}

}  // namespace ml_benchmark
}  // namespace chrome
