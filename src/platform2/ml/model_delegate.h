// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_MODEL_DELEGATE_H_
#define ML_MODEL_DELEGATE_H_

#include <map>
#include <memory>
#include <string>

#include <tensorflow/lite/model.h>

#include "ml/graph_executor_delegate.h"
#include "ml/mojom/model.mojom.h"

namespace ml {

using ::chromeos::machine_learning::mojom::CreateGraphExecutorResult;
using ::chromeos::machine_learning::mojom::GpuDelegateApi;

// Holds 4-byte aligned char[] data suitable for a flatbuffer model.
class AlignedModelData {
 public:
  // Constructs from a std::string. If its .c_str() is not 4-byte aligned, an
  // aligned copy is made.
  explicit AlignedModelData(std::string model_str);

  ~AlignedModelData();

  AlignedModelData(const AlignedModelData&) = delete;
  AlignedModelData& operator=(const AlignedModelData&) = delete;

  // The start of the model data. The result will be 4-byte aligned.
  const char* data() const;
  // The length of the buffer starting at `data()`.
  size_t size() const;

 private:
  // Original std::string containing model data. May be empty.
  std::unique_ptr<std::string> original_model_str_;
  // Aligned copy of the original std::string. May be empty.
  std::unique_ptr<char[]> aligned_copy_;
  size_t aligned_copy_size_;
};

// ModelDelegate does the actual work of building tflite::Interpreter as
// required by the mojom::Model interface. It can also be used independently of
// mojom::Model.
class ModelDelegate {
 public:
  // The `required_inputs` and `required_outputs` arguments specify a mapping
  // from required input / output tensor names to their indices in the TF lite
  // graph, and must outlive this object.
  // `model_data` is backing data for `model` which this class will take
  // ownership of. It will be destroyed *after* `model`.
  // UMA metrics will be logged with the specified `metrics_model_name`.
  ModelDelegate(std::map<std::string, int> required_inputs,
                std::map<std::string, int> required_outputs,
                std::unique_ptr<tflite::FlatBufferModel> model,
                std::unique_ptr<AlignedModelData> model_data,
                const std::string& metrics_model_name);
  // Use when constructed from file where no need to pass the `model_data`.
  ModelDelegate(std::map<std::string, int> required_inputs,
                std::map<std::string, int> required_outputs,
                std::unique_ptr<tflite::FlatBufferModel> model,
                const std::string& metrics_model_name);
  ModelDelegate(const ModelDelegate&) = delete;
  ModelDelegate& operator=(const ModelDelegate&) = delete;

  // Creates a GraphExecutorDelegate, returns CreateGraphExecutorResult::OK if
  // no error happens and `*graph_executor_delegate` will be pointed to the
  // created object. Otherwise returns the error type.
  CreateGraphExecutorResult CreateGraphExecutorDelegate(
      bool use_nnapi,
      bool use_gpu,
      GpuDelegateApi gpu_delegate_api,
      GraphExecutorDelegate** graph_executor_delegate);

 private:
  const std::map<std::string, int> required_inputs_;
  const std::map<std::string, int> required_outputs_;

  // Must be above `model_`.
  const std::unique_ptr<AlignedModelData> model_data_;

  const std::unique_ptr<tflite::FlatBufferModel> model_;

  // Model name as it should appear in UMA histogram names.
  const std::string metrics_model_name_;
};

}  // namespace ml

#endif  // ML_MODEL_DELEGATE_H_
