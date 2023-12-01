// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/model_delegate.h"

#include <algorithm>
#include <memory>
#include <utility>

#include <base/check.h>
#include <base/logging.h>
#include <tensorflow/lite/context.h>
#include <tensorflow/lite/delegates/nnapi/nnapi_delegate.h>
#include <tensorflow/lite/delegates/gpu/delegate.h>
#include <tensorflow/lite/interpreter.h>
#include <tensorflow/lite/kernels/register.h>

#include "ml/custom_ops/transpose_conv_bias.h"
#include "ml/request_metrics.h"

namespace ml {
namespace {

// Base name for UMA metrics related to CreateGraphExecutor calls
constexpr char kMetricsRequestName[] = "CreateGraphExecutorResult";
}  // namespace

AlignedModelData::AlignedModelData(std::string model_str) {
  if (reinterpret_cast<std::uintptr_t>(model_str.c_str()) % 4 == 0) {
    // `model_str` is aligned. Keep it.
    original_model_str_ = std::make_unique<std::string>(std::move(model_str));
    aligned_copy_ = nullptr;
    aligned_copy_size_ = 0;
  } else {
    // `model_str` is unaligned. Discard it and make an aligned copy.
    aligned_copy_.reset(new char[model_str.size()]);
    std::copy(model_str.begin(), model_str.end(), aligned_copy_.get());
    aligned_copy_size_ = model_str.size();
  }
}

const char* AlignedModelData::data() const {
  return aligned_copy_ ? aligned_copy_.get() : original_model_str_->c_str();
}

size_t AlignedModelData::size() const {
  return aligned_copy_ ? aligned_copy_size_ : original_model_str_->size();
}

AlignedModelData::~AlignedModelData() = default;

ModelDelegate::ModelDelegate(std::map<std::string, int> required_inputs,
                             std::map<std::string, int> required_outputs,
                             std::unique_ptr<tflite::FlatBufferModel> model,
                             std::unique_ptr<AlignedModelData> model_data,
                             const std::string& metrics_model_name)
    : required_inputs_(std::move(required_inputs)),
      required_outputs_(std::move(required_outputs)),
      model_data_(std::move(model_data)),
      model_(std::move(model)),
      metrics_model_name_(metrics_model_name) {}

ModelDelegate::ModelDelegate(std::map<std::string, int> required_inputs,
                             std::map<std::string, int> required_outputs,
                             std::unique_ptr<tflite::FlatBufferModel> model,
                             const std::string& metrics_model_name)
    : ModelDelegate(std::move(required_inputs),
                    std::move(required_outputs),
                    std::move(model),
                    nullptr /*model_data*/,
                    metrics_model_name) {}

TfLiteGpuDelegateOptionsV2 MakeGpuDelegateOptions(
    GpuDelegateApi gpu_delegate_api) {
  TfLiteGpuDelegateOptionsV2 options(TfLiteGpuDelegateOptionsV2Default());

  switch (gpu_delegate_api) {
    case GpuDelegateApi::OPENCL:
      options.experimental_flags |= TFLITE_GPU_EXPERIMENTAL_FLAGS_CL_ONLY;
      break;
    default:
      options.experimental_flags |= TFLITE_GPU_EXPERIMENTAL_FLAGS_GL_ONLY;
  }

  return options;
}

CreateGraphExecutorResult ModelDelegate::CreateGraphExecutorDelegate(
    const bool use_nnapi,
    const bool use_gpu,
    GpuDelegateApi gpu_delegate_api,
    GraphExecutorDelegate** graph_executor_delegate) {
  DCHECK(!metrics_model_name_.empty());

  RequestMetrics request_metrics(metrics_model_name_, kMetricsRequestName);
  request_metrics.StartRecordingPerformanceMetrics();

  if (model_ == nullptr) {
    LOG(ERROR) << "Null model provided.";
    request_metrics.RecordRequestEvent(
        CreateGraphExecutorResult::MODEL_INTERPRETATION_ERROR);
    return CreateGraphExecutorResult::MODEL_INTERPRETATION_ERROR;
  }

  // Instantiate interpreter.
  tflite::ops::builtin::BuiltinOpResolver resolver;
  resolver.AddCustom("Convolution2DTransposeBias",
                     custom_ops::RegisterConvolution2DTransposeBias());
  std::unique_ptr<tflite::Interpreter> interpreter;
  const TfLiteStatus resolve_status =
      tflite::InterpreterBuilder(*model_, resolver)(&interpreter);
  if (resolve_status != kTfLiteOk || !interpreter) {
    LOG(ERROR) << "Could not resolve model ops.";
    request_metrics.RecordRequestEvent(
        CreateGraphExecutorResult::MODEL_INTERPRETATION_ERROR);
    return CreateGraphExecutorResult::MODEL_INTERPRETATION_ERROR;
  }

  // Check that any chosen delegates are mutually exclusive
  if (use_nnapi && use_gpu) {
    LOG(ERROR) << "Cannot specify GPU and NNAPI delegates simultaneously.";
    request_metrics.RecordRequestEvent(
        CreateGraphExecutorResult::DELEGATE_CONFIG_ERROR);
    return CreateGraphExecutorResult::DELEGATE_CONFIG_ERROR;
  }

  // If requested, load and apply NNAPI
  if (use_nnapi) {
    TfLiteDelegate* delegate = tflite::NnApiDelegate();
    if (!delegate) {
      LOG(ERROR) << "NNAPI requested but not available.";
      request_metrics.RecordRequestEvent(
          CreateGraphExecutorResult::NNAPI_UNAVAILABLE);
      return CreateGraphExecutorResult::NNAPI_UNAVAILABLE;
    }
    if (interpreter->ModifyGraphWithDelegate(delegate) != kTfLiteOk) {
      LOG(ERROR) << "Could not use NNAPI delegate.";
      request_metrics.RecordRequestEvent(
          CreateGraphExecutorResult::NNAPI_USE_ERROR);
      return CreateGraphExecutorResult::NNAPI_USE_ERROR;
    }
  }

  // If requested, load and apply GPU
  if (use_gpu) {
    TfLiteGpuDelegateOptionsV2 options(
        MakeGpuDelegateOptions(gpu_delegate_api));
    TfLiteDelegate* delegate = TfLiteGpuDelegateV2Create(&options);
    if (!delegate) {
      LOG(ERROR) << "GPU requested but not available.";
      request_metrics.RecordRequestEvent(
          CreateGraphExecutorResult::GPU_UNAVAILABLE);
      return CreateGraphExecutorResult::GPU_UNAVAILABLE;
    }
    if (interpreter->ModifyGraphWithDelegate(delegate) != kTfLiteOk) {
      LOG(ERROR) << "Could not use GPU delegate.";
      request_metrics.RecordRequestEvent(
          CreateGraphExecutorResult::GPU_USE_ERROR);
      return CreateGraphExecutorResult::GPU_USE_ERROR;
    }
  }

  // If delegating, fail unless delegate can process the entire model.
  // We don't want partitioned execution (for now).
  if (use_nnapi || use_gpu) {
    bool fully_delegated = false;
    // A fully delegated model should have only one node that has a delegate.
    if (interpreter->execution_plan().size() == 1) {
      int node_id = interpreter->execution_plan()[0];
      const TfLiteNode& node =
          interpreter->node_and_registration(node_id)->first;
      if (node.delegate != nullptr) {
        fully_delegated = true;
      }
    }
    if (!fully_delegated) {
      LOG(ERROR) << "Model couldn't be fully delegated.";
      request_metrics.RecordRequestEvent(
          CreateGraphExecutorResult::NOT_FULLY_DELEGABLE);
      return CreateGraphExecutorResult::NOT_FULLY_DELEGABLE;
    }
  }

  // Allocate memory for tensors.
  if (interpreter->AllocateTensors() != kTfLiteOk) {
    request_metrics.RecordRequestEvent(
        CreateGraphExecutorResult::MEMORY_ALLOCATION_ERROR);
    return CreateGraphExecutorResult::MEMORY_ALLOCATION_ERROR;
  }

  *graph_executor_delegate =
      new GraphExecutorDelegate(required_inputs_, required_outputs_,
                                std::move(interpreter), metrics_model_name_);

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(CreateGraphExecutorResult::OK);
  return CreateGraphExecutorResult::OK;
}

}  // namespace ml
