// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_DBUS_SERVICE_TF_MODEL_GRAPH_EXECUTOR_H_
#define ML_DBUS_SERVICE_TF_MODEL_GRAPH_EXECUTOR_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "chrome/knowledge/assist_ranker/example_preprocessor.pb.h"
#include "chrome/knowledge/assist_ranker/ranker_example.pb.h"
#include "ml/graph_executor_delegate.h"
#include "ml/model_delegate.h"
#include "ml/model_metadata.h"

namespace ml {

using ::chromeos::machine_learning::mojom::BuiltinModelId;
using ::chromeos::machine_learning::mojom::TensorPtr;

// TfModelGraphExecutor is responsible for the real machine learning related
// jobs, including vectorizing feature example and tflite model inference.
// It's initialized with a model and a perprocessor config. Currently it only
// supports loading builtin model.
class TfModelGraphExecutor {
 public:
  TfModelGraphExecutor(BuiltinModelId model_id,
                       const std::string& preprocessor_file_name);
  TfModelGraphExecutor(const TfModelGraphExecutor&) = delete;
  TfModelGraphExecutor& operator=(const TfModelGraphExecutor&) = delete;
  ~TfModelGraphExecutor();

  // Whether the object is ready to do inference. Must be verified to be true
  // before calling Execute.
  bool Ready() const;

  // Preprocesses `example` with `config_` and runs the tensorflow graph with
  // the vectorized features, extracts the outputs and appends to
  // `output_tensors`.
  bool Execute(bool clear_other_features,
               assist_ranker::RankerExample* example,
               std::vector<TensorPtr>* output_tensors) const;

  // Creates an instance with given asset_dir for testing.
  static std::unique_ptr<TfModelGraphExecutor> CreateForTesting(
      BuiltinModelId model_id,
      const std::string& preprocessor_file_name,
      const std::string& asset_dir);

 private:
  // Constructor that allows overriding of the asset dir.
  TfModelGraphExecutor(BuiltinModelId model_id,
                       const std::string& preprocessor_file_name,
                       const std::string& asset_dir);

  const std::string asset_dir_;
  std::vector<std::string> output_names_;

  std::unique_ptr<assist_ranker::ExamplePreprocessorConfig> config_;
  std::unique_ptr<ModelDelegate> model_delegate_;
  std::unique_ptr<GraphExecutorDelegate> graph_executor_delegate_;
};

}  // namespace ml

#endif  // ML_DBUS_SERVICE_TF_MODEL_GRAPH_EXECUTOR_H_
