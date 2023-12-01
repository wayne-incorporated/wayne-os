// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/dbus_service/tf_model_graph_executor_util.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace ml {

namespace {
using assist_ranker::ExamplePreprocessor;
}  // namespace

TEST(TfModelGraphExecutorTest, AcceptablePreprocessResult) {
  EXPECT_TRUE(AcceptablePreprocessResult(ExamplePreprocessor::kSuccess));
  EXPECT_TRUE(
      AcceptablePreprocessResult(ExamplePreprocessor::kNoFeatureIndexFound));
  EXPECT_TRUE(AcceptablePreprocessResult(
      ExamplePreprocessor::kNonNormalizableFeatureType));
  EXPECT_TRUE(AcceptablePreprocessResult(
      ExamplePreprocessor::kNoFeatureIndexFound |
      ExamplePreprocessor::kNonNormalizableFeatureType));
  EXPECT_FALSE(
      AcceptablePreprocessResult(ExamplePreprocessor::kInvalidFeatureType));
  EXPECT_FALSE(AcceptablePreprocessResult(
      ExamplePreprocessor::kInvalidFeatureListIndex));
  EXPECT_FALSE(AcceptablePreprocessResult(
      ExamplePreprocessor::kSuccess |
      ExamplePreprocessor::kInvalidFeatureListIndex));
}

}  // namespace ml
