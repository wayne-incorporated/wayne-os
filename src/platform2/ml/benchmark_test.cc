// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <google/protobuf/text_format.h>
#include <gtest/gtest.h>

#include "ml/benchmark.h"
#include "ml/benchmark.pb.h"
#include "ml/mojom/model.mojom.h"
#include "proto/benchmark_config.pb.h"

namespace ml {

using ::chrome::ml_benchmark::BenchmarkResults;
using ::chrome::ml_benchmark::BenchmarkReturnStatus;
using ::chrome::ml_benchmark::CrOSBenchmarkConfig;
using ::google::protobuf::TextFormat;

// Test model
constexpr char kSmartDim20181115ModelFile[] =
    "/opt/google/chrome/ml_models/mlservice-model-test_add-20180914.tflite";

// Test input.
constexpr char kModelProtoText[] = R"(
  required_inputs: {
    key: "x"
    value: {
      index: 1
      dims: [1]
    }
  }
  required_inputs: {
    key: "y"
    value: {
      index: 2
      dims: [1]
    }
  }
  required_outputs: {
    key: "z"
    value: {
      index: 0
      dims: [1]
    }
  }
)";
constexpr char kInputOutputText[] = R"(
  input: {
    features: {
      feature: {
        key: "x"
        value: {
          float_list: { value:[ 0.5 ] }
        }
      }
      feature: {
        key: "y"
        value: {
          float_list: { value:[ 0.25 ] }
        }
      }
    }
  }
  expected_output:{
    features: {
      feature: {
        key: "z"
        value: {
          float_list: { value: [ 0.75 ] }
        }
      }
    }
  }
)";

class MlBenchmarkTest : public ::testing::Test {
 public:
  MlBenchmarkTest() {
    // Set benchmark_config_;
    CHECK(temp_dir_.CreateUniqueTempDir());
    const base::FilePath tflite_model_filepath =
        temp_dir_.GetPath().Append("model.pb");
    input_output_filepath_ = temp_dir_.GetPath().Append("input_output.pb");
    TfliteBenchmarkConfig tflite_config;
    tflite_config.set_tflite_model_filepath(tflite_model_filepath.value());
    tflite_config.set_input_output_filepath(input_output_filepath_.value());
    tflite_config.set_num_runs(100);
    TextFormat::PrintToString(tflite_config,
                              benchmark_config_.mutable_driver_config());

    // Set FlatBufferModelSpecProto;
    FlatBufferModelSpecProto model_proto;
    CHECK(TextFormat::ParseFromString(kModelProtoText, &model_proto));
    base::ReadFileToString(base::FilePath(kSmartDim20181115ModelFile),
                           model_proto.mutable_model_string());
    const std::string model_content = model_proto.SerializeAsString();
    base::WriteFile(tflite_model_filepath, model_content.data(),
                    model_content.size());

    // Set ExpectedInputOutput.
    SetExpectedValue(0.75f);
  }
  MlBenchmarkTest(const MlBenchmarkTest&) = delete;
  MlBenchmarkTest& operator=(const MlBenchmarkTest&) = delete;

  // Write the output with given expected value.
  void SetExpectedValue(const float val) {
    ExpectedInputOutput input_output;
    CHECK(TextFormat::ParseFromString(kInputOutputText, &input_output));
    (*(*input_output.mutable_expected_output()
            ->mutable_features()
            ->mutable_feature())["z"]
          .mutable_float_list()
          ->mutable_value())[0] = val;
    const std::string input_content = input_output.SerializeAsString();
    base::WriteFile(input_output_filepath_, input_content.data(),
                    input_content.size());
  }

 protected:
  // Temporary directory containing a file used for the file mechanism.
  base::ScopedTempDir temp_dir_;
  base::FilePath input_output_filepath_;
  CrOSBenchmarkConfig benchmark_config_;
};

TEST_F(MlBenchmarkTest, TfliteModelMatchedValueTest) {
  // Step 1 run benchmark_start.
  const std::string config = benchmark_config_.SerializeAsString();
  void* results_data = nullptr;
  int results_size = 0;
  EXPECT_EQ(benchmark_start(config.c_str(), config.size(), &results_data,
                            &results_size),
            BenchmarkReturnStatus::OK);

  // Step 2 check results.
  BenchmarkResults results;
  CHECK(results.ParseFromArray(results_data, results_size));
  free_benchmark_results(results_data);
  EXPECT_EQ(results.status(), BenchmarkReturnStatus::OK);
  EXPECT_EQ(results.power_normalization_factor(), 100);

  auto latencies = results.percentile_latencies_in_us();
  EXPECT_EQ(latencies.size(), 4);
  EXPECT_TRUE(0 <= latencies[50] && latencies[50] <= latencies[90] &&
              latencies[90] <= latencies[95] && latencies[95] <= latencies[99]);

  auto& metrics = results.metrics();
  EXPECT_EQ(metrics[0].name(), "average_error");
  EXPECT_EQ(metrics[0].units(), chrome::ml_benchmark::Metric::UNITLESS);
  EXPECT_EQ(metrics[0].direction(),
            chrome::ml_benchmark::Metric::SMALLER_IS_BETTER);
  EXPECT_EQ(metrics[0].cardinality(), chrome::ml_benchmark::Metric::SINGLE);
  EXPECT_NEAR(metrics[0].values()[0], 0.0f, 1e-5);

  EXPECT_EQ(metrics[1].name(), "50th_perc_cpu_time");
  EXPECT_EQ(metrics[1].units(), chrome::ml_benchmark::Metric::MS);
  EXPECT_EQ(metrics[1].direction(),
            chrome::ml_benchmark::Metric::SMALLER_IS_BETTER);
  EXPECT_EQ(metrics[1].cardinality(), chrome::ml_benchmark::Metric::SINGLE);
  EXPECT_GE(metrics[1].values()[0], 0.0f);

  EXPECT_EQ(metrics[2].name(), "90th_perc_cpu_time");
  EXPECT_GE(metrics[2].values()[0], metrics[1].values()[0]);
  EXPECT_EQ(metrics[3].name(), "95th_perc_cpu_time");
  EXPECT_GE(metrics[3].values()[0], metrics[2].values()[0]);
  EXPECT_EQ(metrics[4].name(), "99th_perc_cpu_time");
  EXPECT_GE(metrics[4].values()[0], metrics[3].values()[0]);
}

TEST_F(MlBenchmarkTest, TfliteModelUnmatchedValueTest) {
  SetExpectedValue(0.76f);
  // Step 1 run benchmark_start.
  const std::string config = benchmark_config_.SerializeAsString();
  void* results_data = nullptr;
  int results_size = 0;
  EXPECT_EQ(benchmark_start(config.c_str(), config.size(), &results_data,
                            &results_size),
            BenchmarkReturnStatus::OK);

  // Step 2 check results.
  BenchmarkResults results;
  CHECK(results.ParseFromArray(results_data, results_size));
  free_benchmark_results(results_data);
  EXPECT_EQ(results.status(), BenchmarkReturnStatus::OK);
  auto metrics = results.metrics();
  EXPECT_EQ(metrics[0].name(), "average_error");
  EXPECT_EQ(metrics[0].units(), chrome::ml_benchmark::Metric::UNITLESS);
  EXPECT_EQ(metrics[0].direction(),
            chrome::ml_benchmark::Metric::SMALLER_IS_BETTER);
  EXPECT_EQ(metrics[0].cardinality(), chrome::ml_benchmark::Metric::SINGLE);
  EXPECT_NEAR(metrics[0].values()[0], 0.01f, 1e-5);
}

}  // namespace ml
