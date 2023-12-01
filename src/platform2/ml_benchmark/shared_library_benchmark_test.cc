// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/shared_library_benchmark.h"

#include <gmock/gmock.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>

#include <functional>
#include <string>

#include "ml_benchmark/benchmark_functions.h"
#include "proto/benchmark_config.pb.h"

namespace ml_benchmark {

using chrome::ml_benchmark::BenchmarkResults;
using chrome::ml_benchmark::CrOSBenchmarkConfig;
using google::protobuf::util::MessageDifferencer;
using testing::Expectation;

class MockBenchmarkFunctions : public BenchmarkFunctions {
 public:
  MOCK_METHOD(int32_t,
              BenchmarkFunction,
              (const void*, int32_t, void**, int32_t*),
              (override));

  MOCK_METHOD(void, FreeBenchmarkResults, (void*), (override));
};

class SharedLibraryBenchmarkTest : public ::testing::Test {
 protected:
  void SetUp() override {
    functions_ = std::make_unique<MockBenchmarkFunctions>();
  }

  void SetReturnResult(const BenchmarkResults& result) {
    return_buffer_ = result.SerializeAsString();

    ON_CALL(*functions_.get(), BenchmarkFunction)
        .WillByDefault([this, result](const void* buf, int32_t buf_len,
                                      void** results_bytes,
                                      int32_t* results_len) {
          *results_bytes = const_cast<void*>(
              reinterpret_cast<const void*>(return_buffer_.c_str()));
          *results_len = return_buffer_.size();

          return result.status();
        });
  }

  std::unique_ptr<MockBenchmarkFunctions> functions_;
  std::string return_buffer_;
};

// Testing the contracts that the benchmark loader has with
// benchmark drivers
TEST_F(SharedLibraryBenchmarkTest, benchmark_success) {
  BenchmarkResults expected_results;
  expected_results.set_status(chrome::ml_benchmark::OK);
  expected_results.set_results_message("success");

  SetReturnResult(expected_results);

  using ::testing::InSequence;
  {
    InSequence seq;

    EXPECT_CALL(*functions_, BenchmarkFunction).Times(1);
    EXPECT_CALL(*functions_, FreeBenchmarkResults).Times(1);
  }

  CrOSBenchmarkConfig config;
  BenchmarkResults actual_results;
  SharedLibraryBenchmark benchmark(std::move(functions_));
  bool success = benchmark.ExecuteBenchmark(config, &actual_results);

  ASSERT_TRUE(success);
  ASSERT_TRUE(MessageDifferencer::Equals(expected_results, actual_results));
}

}  // namespace ml_benchmark
