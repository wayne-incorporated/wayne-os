// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_DBUS_SERVICE_TF_MODEL_GRAPH_EXECUTOR_UTIL_H_
#define ML_DBUS_SERVICE_TF_MODEL_GRAPH_EXECUTOR_UTIL_H_

#include "ml/example_preprocessor/example_preprocessing.h"

namespace ml {
// Take a code return from assist_ranker::ExamplePreprocessor::Process,
// determine if this is a acceptable result.
// As ExamplePreprocessor::kNoFeatureIndexFound and
// ExamplePreprocessor::kNonNormalizableFeatureType can occur normally, if we
// encounter one (or both) of these, it is not treated as an error.
bool AcceptablePreprocessResult(int code);
}  // namespace ml

#endif  // ML_DBUS_SERVICE_TF_MODEL_GRAPH_EXECUTOR_UTIL_H_
