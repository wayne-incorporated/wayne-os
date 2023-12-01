// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/dbus_service/tf_model_graph_executor.h"

#include <cstdint>
#include <memory>
#include <utility>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <tensorflow/lite/model.h>

#include "chrome/knowledge/assist_ranker/ranker_example.pb.h"
#include "ml/dbus_service/tf_model_graph_executor_util.h"
#include "ml/example_preprocessor/example_preprocessing.h"
#include "ml/mojom/model.mojom.h"
#include "ml/request_metrics.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::CreateGraphExecutorResult;
using ::chromeos::machine_learning::mojom::FloatList;
using ::chromeos::machine_learning::mojom::GpuDelegateApi;
using ::chromeos::machine_learning::mojom::Int64List;
using ::chromeos::machine_learning::mojom::Tensor;
using ::chromeos::machine_learning::mojom::ValueList;

constexpr char kSystemModelDir[] = "/opt/google/chrome/ml_models/";
// TODO(alanlxl):  need to modify xml to support
// MachineLearningService.<model_name>.TfModelGraphExecutor.Event,
// We don't log memory and time cost here, because they are logged by
// ModelDelegate and GraphExecutorDelegate.
constexpr char kMetricsRequestName[] = "TfModelGraphExecutor";

enum class TfModelGraphExecutorEvent {
  kOk = 0,
  kReadBuiltinModelError = 1,
  kCreateGraphExecutorError = 2,
  kInitializePreprocessorError = 3,
  kMaxValue = kInitializePreprocessorError,
};

}  // namespace

TfModelGraphExecutor::TfModelGraphExecutor(
    BuiltinModelId model_id,
    const std::string& preprocessor_file_name,
    const std::string& asset_dir)
    : asset_dir_(asset_dir) {
  // Unsupported models do not have metadata entries.
  const auto builtin_model_metadata = GetBuiltinModelMetadata();
  const auto metadata_lookup = builtin_model_metadata.find(model_id);
  if (metadata_lookup == builtin_model_metadata.end()) {
    LOG(ERROR) << "Construct TfModelGraphExecutor with unsupported model ID "
               << model_id;
    return;
  }

  const BuiltinModelMetadata& metadata = metadata_lookup->second;

  DCHECK(!metadata.metrics_model_name.empty());

  RequestMetrics request_metrics(metadata.metrics_model_name,
                                 kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  // Attempts to load model.
  const std::string model_path = asset_dir_ + metadata.model_file;
  std::unique_ptr<tflite::FlatBufferModel> flat_buffer_model =
      tflite::FlatBufferModel::BuildFromFile(model_path.c_str());
  if (flat_buffer_model == nullptr) {
    LOG(ERROR) << "Failed to load model file '" << model_path << "'.";
    request_metrics.RecordRequestEvent(
        TfModelGraphExecutorEvent::kReadBuiltinModelError);
    return;
  }

  model_delegate_ = std::make_unique<ModelDelegate>(
      metadata.required_inputs, metadata.required_outputs,
      std::move(flat_buffer_model), metadata.metrics_model_name);

  for (const auto& kv : metadata.required_outputs) {
    output_names_.push_back(kv.first);
  }

  GraphExecutorDelegate* graph_executor_delegate;
  if (model_delegate_->CreateGraphExecutorDelegate(
          false /*use_nnapi*/, false /*use_gpu*/,
          GpuDelegateApi::OPENGL /*gpu_delegate_api*/,
          &graph_executor_delegate) != CreateGraphExecutorResult::OK) {
    request_metrics.RecordRequestEvent(
        TfModelGraphExecutorEvent::kCreateGraphExecutorError);
    return;
  }
  graph_executor_delegate_.reset(graph_executor_delegate);

  // Attempts to read the preprocessor config.
  config_ = std::make_unique<assist_ranker::ExamplePreprocessorConfig>();
  std::string preprocessor_proto;
  if (!base::ReadFileToString(
          base::FilePath(asset_dir_ + preprocessor_file_name),
          &preprocessor_proto) ||
      !config_->ParseFromString(preprocessor_proto)) {
    LOG(ERROR) << "Failed to read preprocessor from " << preprocessor_file_name;
    request_metrics.RecordRequestEvent(
        TfModelGraphExecutorEvent::kInitializePreprocessorError);
    config_.reset();
    return;
  }
}

TfModelGraphExecutor::TfModelGraphExecutor(
    BuiltinModelId model_id, const std::string& preprocessor_file_name)
    : TfModelGraphExecutor(model_id, preprocessor_file_name, kSystemModelDir) {}

TfModelGraphExecutor::~TfModelGraphExecutor() = default;

bool TfModelGraphExecutor::Ready() const {
  return model_delegate_ && graph_executor_delegate_ && config_;
}

bool TfModelGraphExecutor::Execute(
    bool clear_other_features,
    assist_ranker::RankerExample* example,
    std::vector<TensorPtr>* output_tensors) const {
  DCHECK(Ready());
  DCHECK(example);

  const int preprocessor_result = assist_ranker::ExamplePreprocessor::Process(
      *config_, example, clear_other_features);
  if (!AcceptablePreprocessResult(preprocessor_result)) {
    LOG(ERROR) << "Preprocess example failed! Error type = "
               << preprocessor_result;
    return false;
  }

  const auto& extracted_features =
      example->features()
          .at(assist_ranker::ExamplePreprocessor::kVectorizedFeatureDefaultName)
          .float_list()
          .float_value();
  const std::vector<float> vectorized_features(extracted_features.begin(),
                                               extracted_features.end());

  base::flat_map<std::string, TensorPtr> inputs;
  auto tensor = Tensor::New();
  tensor->shape = Int64List::New();
  tensor->shape->value = std::vector<int64_t>(
      {1, static_cast<int64_t>(vectorized_features.size())});
  tensor->data = ValueList::NewFloatList(FloatList::New());
  tensor->data->get_float_list()->value = std::vector<double>(
      std::begin(vectorized_features), std::end(vectorized_features));
  // "input" is the input node name hardcoded in ../model_metadata.cc.
  inputs.emplace("input", std::move(tensor));

  auto execute_result = graph_executor_delegate_->Execute(
      std::move(inputs), output_names_, *output_tensors);

  return execute_result == ExecuteResult::OK;
}

// static
std::unique_ptr<TfModelGraphExecutor> TfModelGraphExecutor::CreateForTesting(
    BuiltinModelId model_id,
    const std::string& preprocessor_file_name,
    const std::string& assert_dir) {
  return base::WrapUnique(
      new TfModelGraphExecutor(model_id, preprocessor_file_name, assert_dir));
}

}  // namespace ml
