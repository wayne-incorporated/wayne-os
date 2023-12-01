// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/dbus_service/tf_model_graph_executor.h"

#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "chrome/knowledge/assist_ranker/ranker_example.pb.h"
#include "ml/tensor_view.h"
#include "ml/test_utils.h"

namespace ml {
namespace {
constexpr char kPreprocessorFileNameForSmartDim20190521[] =
    "mlservice-model-smart_dim-20190521-preprocessor.pb";
constexpr char kPreprocessorFileNameForAdaptiveCharging20230314[] =
    "mlservice-model-adaptive_charging-20230314-preprocessor.pb";
constexpr char kBadPreprocessorFileName[] = "non-exist.pb";

using ::chromeos::machine_learning::mojom::BuiltinModelId;
using ::chromeos::machine_learning::mojom::TensorPtr;

using ::testing::DoubleNear;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Matcher;

std::vector<Matcher<double>> ArrayDoubleNear(const std::vector<double>& values,
                                             double max_abs_error = 1.e-5) {
  std::vector<Matcher<double>> matchers;
  matchers.reserve(values.size());
  for (const double& v : values) {
    matchers.push_back(DoubleNear(v, max_abs_error));
  }
  return matchers;
}

}  // namespace

// Constructs with bad preprocessor config file.
TEST(TfModelGraphExecutorTest, ConstructWithBadPreprocessorConfig) {
  const auto tf_model_graph_executor = TfModelGraphExecutor::CreateForTesting(
      BuiltinModelId::SMART_DIM_20190521, kBadPreprocessorFileName,
      GetTestModelDir());
  EXPECT_FALSE(tf_model_graph_executor->Ready());
}

// Constructs with unsupported BuiltinModelId.
TEST(TfModelGraphExecutorTest, ConstructWithBadModelId) {
  const auto tf_model_graph_executor = TfModelGraphExecutor::CreateForTesting(
      BuiltinModelId::UNSUPPORTED_UNKNOWN,
      kPreprocessorFileNameForSmartDim20190521, GetTestModelDir());
  EXPECT_FALSE(tf_model_graph_executor->Ready());
}

// Constructs a valid tf_model_graph_executor with valid model and preprocessor.
TEST(TfModelGraphExecutorTest, ConstructSuccess) {
  const auto tf_model_graph_executor = TfModelGraphExecutor::CreateForTesting(
      BuiltinModelId::SMART_DIM_20190521,
      kPreprocessorFileNameForSmartDim20190521, GetTestModelDir());
  EXPECT_TRUE(tf_model_graph_executor->Ready());
}

// Tests that TfModelGraphExecutor works with smart_dim_20190521 assets.
TEST(TfModelGraphExecutorTest, ExecuteSmartDim20190521) {
  const auto tf_model_graph_executor = TfModelGraphExecutor::CreateForTesting(
      BuiltinModelId::SMART_DIM_20190521,
      kPreprocessorFileNameForSmartDim20190521, GetTestModelDir());
  ASSERT_TRUE(tf_model_graph_executor->Ready());

  assist_ranker::RankerExample example;
  std::vector<TensorPtr> output_tensors;

  ASSERT_TRUE(tf_model_graph_executor->Execute(true /*clear_other_features*/,
                                               &example, &output_tensors));

  // Check that the output tensor has the right type and format.
  const TensorView<double> out_tensor_view(output_tensors[0]);
  ASSERT_TRUE(out_tensor_view.IsValidType());
  ASSERT_TRUE(out_tensor_view.IsValidFormat());

  // Check the output tensor has the expected shape and values.
  std::vector<int64_t> expected_shape{1L, 1L};
  const double expected_output = -0.625682;
  EXPECT_EQ(out_tensor_view.GetShape(), expected_shape);
  EXPECT_THAT(out_tensor_view.GetValues(),
              ElementsAre(DoubleNear(expected_output, 1e-5)));
}

// Tests that TfModelGraphExecutor works with adaptive_charging_20230314 assets.
TEST(TfModelGraphExecutorTest, ExecuteAdaptiveCharging20230314) {
  const auto tf_model_graph_executor = TfModelGraphExecutor::CreateForTesting(
      BuiltinModelId::ADAPTIVE_CHARGING_20230314,
      kPreprocessorFileNameForAdaptiveCharging20230314, GetTestModelDir());
  ASSERT_TRUE(tf_model_graph_executor->Ready());

  assist_ranker::RankerExample example;
  std::vector<TensorPtr> output_tensors;
  EXPECT_TRUE(tf_model_graph_executor->Execute(true /*clear_other_features*/,
                                               &example, &output_tensors));

  ASSERT_EQ(output_tensors.size(), 1u);
  // Check that the output tensor has the right type and format.
  const TensorView<double> out_tensor_view(output_tensors[0]);
  EXPECT_TRUE(out_tensor_view.IsValidType());
  EXPECT_TRUE(out_tensor_view.IsValidFormat());

  // Check the output tensor has the expected shape and values.
  std::vector<int64_t> expected_shape{1L, 9L};
  EXPECT_EQ(out_tensor_view.GetShape(), expected_shape);
  EXPECT_THAT(out_tensor_view.GetValues(),
              ElementsAreArray(ArrayDoubleNear(
                  {0.207927, 0.187088, 0.121717, 0.090703, 0.065328, 0.045972,
                   0.026243, 0.018707, 0.236313})));
}

}  // namespace ml
