// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_GRAPH_EXECUTOR_DELEGATE_H_
#define ML_GRAPH_EXECUTOR_DELEGATE_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/containers/flat_map.h>
#include <tensorflow/lite/model.h>

#include "ml/mojom/graph_executor.mojom.h"
#include "ml/mojom/tensor.mojom.h"

namespace ml {

using ::chromeos::machine_learning::mojom::ExecuteResult;

// GraphExecutorDelegate does the actual work of calling TFLite as required by
// the mojom::GraphExecutor interface. It can also be used independently of
// mojom::GraphExecutor.
class GraphExecutorDelegate {
 public:
  // The `required_inputs` and `required_outputs` arguments specify a mapping
  // from required input / output tensor names to their indices in the TF lite
  // graph, and must outlive this object.
  //
  // UMA metrics will be logged with the specified `metrics_model_name`.
  //
  // As is standard, `interpreter` must outlive the model with which it was
  // constructed.
  GraphExecutorDelegate(const std::map<std::string, int>& required_inputs,
                        const std::map<std::string, int>& required_outputs,
                        std::unique_ptr<tflite::Interpreter> interpreter,
                        const std::string& metrics_model_name);
  GraphExecutorDelegate(const GraphExecutorDelegate&) = delete;
  GraphExecutorDelegate& operator=(const GraphExecutorDelegate&) = delete;

  // Executes the graph with the given `inputs`, extracts the outputs according
  // to `output_names` and appends to `output_tensors`.
  ExecuteResult Execute(
      base::flat_map<std::string, chromeos::machine_learning::mojom::TensorPtr>
          inputs,
      const std::vector<std::string>& output_names,
      std::vector<chromeos::machine_learning::mojom::TensorPtr>&
          output_tensors);

 private:
  const std::map<std::string, int>& required_inputs_;
  const std::map<std::string, int>& required_outputs_;

  const std::unique_ptr<tflite::Interpreter> interpreter_;
  // Model name as it should appear in UMA histogram names.
  const std::string metrics_model_name_;
};

}  // namespace ml

#endif  // ML_GRAPH_EXECUTOR_DELEGATE_H_
