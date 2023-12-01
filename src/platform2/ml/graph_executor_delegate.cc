// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/graph_executor_delegate.h"

#include <iterator>
#include <set>
#include <utility>

#include <base/check.h>
#include <base/logging.h>

#include "ml/mojom/tensor.mojom.h"
#include "ml/request_metrics.h"
#include "ml/tensor_view.h"

namespace ml {
namespace {
using ::chromeos::machine_learning::mojom::ExecuteResult;
using ::chromeos::machine_learning::mojom::Tensor;
using ::chromeos::machine_learning::mojom::TensorPtr;

// Base name for UMA metrics related to graph execution
constexpr char kMetricsRequestName[] = "ExecuteResult";

// Verifies `tensor` is valid (i.e. is of type `TensorType` and of the correct
// shape for this input) and copies its data into the graph `interpreter` at
// position `index`.
template <typename TensorType, typename MemoryType>
ExecuteResult PopulateInput(const TensorPtr& tensor,
                            const int index,
                            tflite::Interpreter* const interpreter) {
  const TensorView<TensorType> tensor_view(tensor);

  if (!tensor_view.IsValidType())
    return ExecuteResult::INPUT_TYPE_ERROR;

  if (!tensor_view.IsValidFormat())
    return ExecuteResult::INPUT_FORMAT_ERROR;

  // Check that given input shape matches that expected by TF lite.

  const TfLiteIntArray& expected_dims = *interpreter->tensor(index)->dims;
  const std::vector<int64_t>& actual_dims = tensor_view.GetShape();

  bool shape_matches = expected_dims.size == actual_dims.size();
  for (int i = 0; shape_matches && i < expected_dims.size; ++i) {
    shape_matches = expected_dims.data[i] == actual_dims[i];
  }

  if (!shape_matches)
    return ExecuteResult::INPUT_SHAPE_ERROR;

  MemoryType* const input_memory = interpreter->typed_tensor<MemoryType>(index);
  const std::vector<TensorType>& tensor_values = tensor_view.GetValues();
  for (int i = 0; i < tensor_values.size(); ++i) {
    input_memory[i] = tensor_values[i];
  }

  return ExecuteResult::OK;
}

ExecuteResult InvalidInput(const TensorPtr&, int, tflite::Interpreter*) {
  return ExecuteResult::EXECUTION_ERROR;
}

// A table of functions to validate / populate data for model nodes expecting
// input of each TF lite type.
//
// This table is indexed by TfLiteType, the possible values of which can be
// found at <tensorflow/lite/context.h>. We make the following
// assumptions about index values:
//   1) They will remain consistent across TF lite releases, and
//   2) They will always start from (close to) 0 and be (mostly) consecutive.
//
// Since TfLiteType is part of the stable C API for TF lite, these assumptions
// seem fair.
constexpr decltype(&InvalidInput) kPopulateInputFns[] = {
    &InvalidInput,                     // kTfLiteNoType
    &PopulateInput<double, float>,     // kTfLiteFloat32
    &PopulateInput<int64_t, int32_t>,  // kTfLiteInt32
    &PopulateInput<int64_t, uint8_t>,  // kTfLiteUInt8
    &PopulateInput<int64_t, int64_t>,  // kTfLiteInt64
    &InvalidInput,                     // kTfLiteString
    &PopulateInput<int64_t, bool>,     // kTfLiteBool
};

// Copies data from position `index` in the graph `interpreter` into the given
// tensor object.
template <typename TensorType, typename MemoryType>
ExecuteResult PopulateOutput(const int index,
                             const tflite::Interpreter& interpreter,
                             const TensorPtr& tensor) {
  TensorView<TensorType> tensor_view(tensor);
  tensor_view.Allocate();

  // Empty output is not valid.
  const TfLiteIntArray& dims = *interpreter.tensor(index)->dims;
  if (dims.size == 0)
    return ExecuteResult::EXECUTION_ERROR;

  // Copy across size information and calculate the number of elements being
  // output.
  int64_t num_entries = 1;
  std::vector<int64_t>& tensor_dims = tensor_view.GetShape();
  tensor_dims.resize(dims.size);
  for (int i = 0; i < dims.size; ++i) {
    const int64_t dim_length = dims.data[i];

    if (dim_length <= 0)
      return ExecuteResult::EXECUTION_ERROR;

    tensor_dims[i] = dim_length;
    num_entries *= dim_length;
  }

  // Populate tensor values.
  const MemoryType* const output_memory =
      interpreter.typed_tensor<MemoryType>(index);
  std::vector<TensorType>& tensor_values = tensor_view.GetValues();
  tensor_values.resize(num_entries);
  for (int i = 0; i < num_entries; ++i) {
    tensor_values[i] = output_memory[i];
  }

  return ExecuteResult::OK;
}

ExecuteResult InvalidOutput(int, const tflite::Interpreter&, const TensorPtr&) {
  return ExecuteResult::EXECUTION_ERROR;
}

// A table of functions to populate data for tensors from output of each TF lite
// type.
//
// This table is indexed by TfLiteType, the possible values of which can be
// found at <tensorflow/lite/context.h>. See the caveats discussed in
// the comment above `kPopulateInputFns`.
constexpr decltype(&InvalidOutput) kPopulateOutputFns[] = {
    &InvalidOutput,                     // kTfLiteNoType
    &PopulateOutput<double, float>,     // kTfLiteFloat32
    &PopulateOutput<int64_t, int32_t>,  // kTfLiteInt32
    &PopulateOutput<int64_t, uint8_t>,  // kTfLiteUInt8
    &PopulateOutput<int64_t, int64_t>,  // kTfLiteInt64
    &InvalidOutput,                     // kTfLiteString
    &PopulateOutput<int64_t, bool>,     // kTfLiteBool
};

}  // namespace

GraphExecutorDelegate::GraphExecutorDelegate(
    const std::map<std::string, int>& required_inputs,
    const std::map<std::string, int>& required_outputs,
    std::unique_ptr<tflite::Interpreter> interpreter,
    const std::string& metrics_model_name)
    : required_inputs_(required_inputs),
      required_outputs_(required_outputs),
      interpreter_(std::move(interpreter)),
      metrics_model_name_(metrics_model_name) {}

ExecuteResult GraphExecutorDelegate::Execute(
    base::flat_map<std::string, chromeos::machine_learning::mojom::TensorPtr>
        inputs,
    const std::vector<std::string>& output_names,
    std::vector<chromeos::machine_learning::mojom::TensorPtr>& output_tensors) {
  DCHECK(!metrics_model_name_.empty());

  RequestMetrics request_metrics(metrics_model_name_, kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // Validate input and output names (before executing graph, for efficiency).

  for (const auto& kv : inputs) {
    const std::string& cur_input_name = kv.first;

    const auto name_lookup = required_inputs_.find(cur_input_name);
    if (name_lookup == required_inputs_.end() ||
        name_lookup->second >= interpreter_->tensors_size()) {
      request_metrics.RecordRequestEvent(ExecuteResult::UNKNOWN_INPUT_ERROR);
      return ExecuteResult::UNKNOWN_INPUT_ERROR;
    }
  }

  if (inputs.size() != required_inputs_.size()) {
    request_metrics.RecordRequestEvent(ExecuteResult::INPUT_MISSING_ERROR);
    return ExecuteResult::INPUT_MISSING_ERROR;
  }

  std::set<std::string> seen_outputs;
  for (const auto& cur_output_name : output_names) {
    const auto name_lookup = required_outputs_.find(cur_output_name);
    if (name_lookup == required_outputs_.end() ||
        name_lookup->second >= interpreter_->tensors_size()) {
      request_metrics.RecordRequestEvent(ExecuteResult::UNKNOWN_OUTPUT_ERROR);
      return ExecuteResult::UNKNOWN_OUTPUT_ERROR;
    }

    // Specifying the same output twice is an error.
    const auto insert_result = seen_outputs.insert(cur_output_name);
    if (!insert_result.second) {
      request_metrics.RecordRequestEvent(ExecuteResult::DUPLICATE_OUTPUT_ERROR);
      return ExecuteResult::DUPLICATE_OUTPUT_ERROR;
    }
  }
  if (output_names.size() != required_outputs_.size()) {
    request_metrics.RecordRequestEvent(ExecuteResult::OUTPUT_MISSING_ERROR);
    return ExecuteResult::OUTPUT_MISSING_ERROR;
  }

  // Copy input data into the interpreter.
  for (const auto& kv : inputs) {
    const std::string& cur_input_name = kv.first;
    const TensorPtr& cur_input = kv.second;

    // Always valid, by the input name check at the start of this function.
    const int cur_input_id = required_inputs_.find(cur_input_name)->second;

    // Check that the current input node is a supported type.
    const uint32_t cur_input_type = interpreter_->tensor(cur_input_id)->type;
    if (cur_input_type >= std::size(kPopulateInputFns)) {
      LOG(ERROR) << "TF lite graph contains invalid input node " << cur_input_id
                 << " of type " << cur_input_type << ".";
      request_metrics.RecordRequestEvent(ExecuteResult::EXECUTION_ERROR);
      return ExecuteResult::EXECUTION_ERROR;
    }

    // Attempt to copy input data into the current input node.
    const ExecuteResult populate_input_result =
        (*kPopulateInputFns[cur_input_type])(cur_input, cur_input_id,
                                             interpreter_.get());
    if (populate_input_result != ExecuteResult::OK) {
      request_metrics.RecordRequestEvent(populate_input_result);
      return populate_input_result;
    }
  }

  // Execute graph.
  if (interpreter_->Invoke() != kTfLiteOk) {
    LOG(ERROR) << "TF lite graph execution failed unexpectedly.";
    request_metrics.RecordRequestEvent(ExecuteResult::EXECUTION_ERROR);
    return ExecuteResult::EXECUTION_ERROR;
  }

  // Extract output.
  for (const auto& cur_output_name : output_names) {
    output_tensors.push_back(Tensor::New());

    // Always valid, by the output name check at the start of this function.
    const int cur_output_id = required_outputs_.find(cur_output_name)->second;

    // Check that the current output node is a supported type.
    const uint32_t cur_output_type = interpreter_->tensor(cur_output_id)->type;
    if (cur_output_type >= std::size(kPopulateOutputFns)) {
      LOG(ERROR) << "TF lite graph contains invalid output node "
                 << cur_output_id << " of type " << cur_output_type << ".";
      request_metrics.RecordRequestEvent(ExecuteResult::EXECUTION_ERROR);
      return ExecuteResult::EXECUTION_ERROR;
    }
    // Attempt to extract data from the current output node.
    const ExecuteResult populate_output_result =
        (*kPopulateOutputFns[cur_output_type])(cur_output_id, *interpreter_,
                                               *--output_tensors.end());
    if (populate_output_result != ExecuteResult::OK) {
      request_metrics.RecordRequestEvent(populate_output_result);
      return populate_output_result;
    }
  }

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(ExecuteResult::OK);
  return ExecuteResult::OK;
}

}  // namespace ml
