// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/dbus_service/tf_model_graph_executor_util.h"

namespace ml {

namespace {
using assist_ranker::ExamplePreprocessor;
}  // namespace

bool AcceptablePreprocessResult(int code) {
  return !(code ^ ExamplePreprocessor::kSuccess &&
           code ^ ExamplePreprocessor::kNoFeatureIndexFound &&
           code ^ ExamplePreprocessor::kNonNormalizableFeatureType &&
           code ^ ExamplePreprocessor::kNoFeatureIndexFound ^
               ExamplePreprocessor::kNonNormalizableFeatureType);
}

}  // namespace ml
