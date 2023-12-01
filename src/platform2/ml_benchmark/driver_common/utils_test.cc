// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml_benchmark/driver_common/utils.h"

#include <cstdint>
#include <vector>

#include <gmock/gmock.h>
#include <google/protobuf/util/message_differencer.h>
#include <gtest/gtest.h>

#include "proto/benchmark_config.pb.h"

using google::protobuf::util::MessageDifferencer;
using testing::Pair;
using testing::UnorderedElementsAre;

namespace chrome {
namespace ml_benchmark {

class SerializeResultsTest : public ::testing::Test {
 protected:
  void TearDown() override { FreeSerializedResults(results_data_); }

  void* results_data_ = nullptr;
  int32_t results_size_ = 0;
};

// Tests the interface of SerializeResults, and that the returned buffer can
// be parsed and preserves any set fields.
TEST_F(SerializeResultsTest, SerializeResults) {
  BenchmarkResults benchmark_results;
  benchmark_results.set_status(BenchmarkReturnStatus::OK);
  benchmark_results.set_results_message("success");
  benchmark_results.set_power_normalization_factor(100);

  EXPECT_EQ(SerializeResults(benchmark_results, &results_data_, &results_size_),
            BenchmarkReturnStatus::OK);

  EXPECT_EQ(results_size_, 18);
  BenchmarkResults reparsed_benchmark_results;
  ASSERT_TRUE(
      reparsed_benchmark_results.ParseFromArray(results_data_, results_size_));
  EXPECT_TRUE(MessageDifferencer::Equals(benchmark_results,
                                         reparsed_benchmark_results));
}

// Tests the interface of SerializeError, and that the returned buffer can
// be parsed and contains the error code and message.
TEST_F(SerializeResultsTest, SerializeError) {
  EXPECT_EQ(
      SerializeError("failure", BenchmarkReturnStatus::INCORRECT_CONFIGURATION,
                     &results_data_, &results_size_),
      BenchmarkReturnStatus::INCORRECT_CONFIGURATION);

  EXPECT_EQ(results_size_, 11);
  BenchmarkResults parsed_benchmark_results;
  ASSERT_TRUE(
      parsed_benchmark_results.ParseFromArray(results_data_, results_size_));
  EXPECT_EQ(parsed_benchmark_results.status(),
            BenchmarkReturnStatus::INCORRECT_CONFIGURATION);
  EXPECT_EQ(parsed_benchmark_results.results_message(), "failure");
}

TEST(ComputePercentileTest, EmptyIsAlwaysZero) {
  std::vector<int32_t> samples;
  EXPECT_EQ(ComputePercentile(samples, 0), 0);
  EXPECT_EQ(ComputePercentile(samples, 100), 0);
}

TEST(ComputePercentileTest, CappedToEnds) {
  std::vector<int32_t> samples = {0, 1, 2};
  EXPECT_EQ(ComputePercentile(samples, 0), 0);
  EXPECT_EQ(ComputePercentile(samples, -1), 0);
  EXPECT_EQ(ComputePercentile(samples, 100), 2);
  EXPECT_EQ(ComputePercentile(samples, 101), 2);
}

TEST(ComputePercentileTest, CorrectPercentile) {
  std::vector<int32_t> samples = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  EXPECT_EQ(ComputePercentile(samples, 9), 0);
  EXPECT_EQ(ComputePercentile(samples, 10), 0);
  EXPECT_EQ(ComputePercentile(samples, 11), 1);
  EXPECT_EQ(ComputePercentile(samples, 20), 1);
  EXPECT_EQ(ComputePercentile(samples, 90), 8);
  EXPECT_EQ(ComputePercentile(samples, 91), 9);
  EXPECT_EQ(ComputePercentile(samples, 99), 9);
}

TEST(SetPercentileLatenciesTest, Basics) {
  BenchmarkResults benchmark_results;
  std::vector<int32_t> latencies = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
  SetPercentileLatencies(benchmark_results, latencies);
  const auto& percentile_latencies =
      benchmark_results.percentile_latencies_in_us();
  EXPECT_THAT(
      percentile_latencies,
      UnorderedElementsAre(Pair(50, 4), Pair(90, 8), Pair(95, 9), Pair(99, 9)));
}

}  // namespace ml_benchmark
}  // namespace chrome
