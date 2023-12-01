// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/web_platform_model_impl.h"

#include <algorithm>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/notreached.h>
#include <base/time/time.h>
#include <brillo/message_loops/message_loop.h>

#include "base/debug/leak_annotations.h"
#include "ml/machine_learning_service_impl.h"
#include "ml/mojom/big_buffer.mojom.h"
#include "ml/mojom/machine_learning_service.mojom.h"
#include "ml/process.h"
#include "ml/request_metrics.h"

namespace ml {

namespace {

constexpr char kModelName[] = "WebPlatformTfLiteFlatBufferModel";

// The status code for loading model for metrics report. We don't reuse existing
// enums like `model_loader::mojom::LoadModelResult` because they do not exactly
// match.
// Note that the "direct" mojo receiver function of loading a model is
// `WebPlatformModelLoaderImpl::Load`, but the real work is done in this class
// in `WebPlatformModelImpl::Load`. So we can report more detailed events here
// and without passing the `request_metrics` object around.
enum class MetricEventForLoad {
  kSuccess = 0,
  // The input BigBuffer is invalid.
  kInvalidInputBigBuffer = 1,
  // The input BigBuffer is backed by shared buffer but is invalid.
  kInvalidSharedBuffer = 2,
  // The type of the input BigBuffer is unknown.
  kUnknownTypeOfInputBigBuffer = 3,
  // Failed to build the model.
  kBuildModelFailed = 4,
  // Failed to interpret the model.
  kInterpretModelFailed = 5,
  // Failed to allocate tensors.
  kAllocateTensorFailed = 6,
  // `kMaxValue` must equal to the maximum value in this enum.
  kMaxValue = kAllocateTensorFailed,
};

// The status code for computing for metrics report. We don't reuse existing
// enums because they do not exactly match.
enum class MetricEventForCompute {
  kSuccess = 0,
  // The number of input tensors is wrong.
  kIncorrectNumberOfInputs = 1,
  // Some required input tensor is not provided.
  kMissingInput = 2,
  // The input buffer size does match that required by the model.
  kInvalidInputBufferSize = 3,
  // Failed to do the computation.
  kFailToCompute = 4,
  // `kMaxValue` must equal to the maximum value in this enum.
  kMaxValue = kFailToCompute,
};

std::vector<unsigned int> ConvertTfLiteDimensions(
    TfLiteIntArray* tflite_int_array) {
  if (tflite_int_array == nullptr)
    return {};

  std::vector<unsigned int> ret(tflite_int_array->size);
  for (int i = 0; i < tflite_int_array->size; i++) {
    const auto v = tflite_int_array->data[i];
    // TfLiteIntArray's data can be less than 0. But for dimensions, it must be
    // >= 0.
    if (v < 0)
      return {};
    ret[i] = static_cast<unsigned int>(v);
  }
  return ret;
}

// Notice that in the new version of TFLite, kUint16 will be supported.
model_loader::mojom::DataType ConvertTfLiteTypeToMojo(TfLiteType tflite_type) {
  switch (tflite_type) {
    case kTfLiteFloat32:
      return model_loader::mojom::DataType::kFloat32;
    case kTfLiteInt32:
      return model_loader::mojom::DataType::kInt32;
    case kTfLiteUInt8:
      return model_loader::mojom::DataType::kUint8;
    case kTfLiteInt64:
      return model_loader::mojom::DataType::kInt64;
    case kTfLiteBool:
      return model_loader::mojom::DataType::kBool;
    case kTfLiteInt16:
      return model_loader::mojom::DataType::kInt16;
    case kTfLiteInt8:
      return model_loader::mojom::DataType::kInt8;
    case kTfLiteFloat16:
      return model_loader::mojom::DataType::kFloat16;
    case kTfLiteFloat64:
      return model_loader::mojom::DataType::kFloat64;
    case kTfLiteUInt64:
      return model_loader::mojom::DataType::kUint64;
    case kTfLiteUInt32:
      return model_loader::mojom::DataType::kUint32;
    case kTfLiteNoType:
    case kTfLiteString:
    case kTfLiteComplex64:
    case kTfLiteComplex128:
    case kTfLiteResource:
    case kTfLiteVariant:
      return model_loader::mojom::DataType::kUnknown;
  }
}

}  // namespace

void WebPlatformModelImpl::Create(
    mojo_base::mojom::BigBufferPtr model_content,
    WebPlatformModelLoaderImpl::LoadCallback callback,
    WebPlatformModelLoaderImpl* loader) {
  mojo::PendingRemote<ml::model_loader::mojom::Model> remote;

  auto model_loaded_impl =
      new WebPlatformModelImpl(remote.InitWithNewPipeAndPassReceiver(), loader);

  if (!model_loaded_impl->Load(std::move(model_content), callback)) {
    // In this case, the `callback` has been called (including returning the
    // error messages to the remote process) in `Load()` already.
    delete model_loaded_impl;
  } else {
    loader->RegisterModel();
    model_loaded_impl->receiver_.set_disconnect_handler(
        base::BindOnce(&WebPlatformModelImpl::DefaultDisconnectHandler,
                       base::Unretained(model_loaded_impl)));
    std::move(callback).Run(model_loader::mojom::LoadModelResult::kOk,
                            std::move(remote),
                            model_loaded_impl->GetModelInfo());
  }
}

WebPlatformModelImpl::WebPlatformModelImpl(
    mojo::PendingReceiver<model_loader::mojom::Model> receiver,
    WebPlatformModelLoaderImpl* loader)
    : loader_(loader), receiver_(this, std::move(receiver)) {}

void WebPlatformModelImpl::DefaultDisconnectHandler() {
  const auto remaining_models = loader_->UnregisterModel();
  if (remaining_models == 0 && !loader_->IsValid()) {
    brillo::MessageLoop::current()->BreakLoop();
  } else {
    delete this;
  }
}

void WebPlatformModelImpl::BuildModelFromBytes(
    mojo_base::mojom::BigBufferPtr& model_content) {
  const auto incoming_pointer =
      reinterpret_cast<char*>(model_content->get_bytes().data());

  // Checks alignment. TfLite requires the model buffer to be 32bit aligned.
  if (reinterpret_cast<std::uintptr_t>(incoming_pointer) % 4 == 0) {
    model_big_buffer_ptr_ = std::move(model_content);
    model_ = tflite::FlatBufferModel::VerifyAndBuildFromBuffer(
        incoming_pointer, model_big_buffer_ptr_->get_bytes().size());
  } else {
    model_size_ = model_content->get_bytes().size();
    // The buffer returned from `new` is always aligned.
    model_content_.reset(new char[model_size_]);
    memcpy(model_content_.get(), incoming_pointer, model_size_);
    model_ = tflite::FlatBufferModel::VerifyAndBuildFromBuffer(
        model_content_.get(), model_size_);
  }
}

bool WebPlatformModelImpl::BuildModelFromSharedBuffer(
    mojo_base::mojom::BigBufferPtr& model_content,
    WebPlatformModelLoaderImpl::LoadCallback& callback) {
  // If it is shared memory, for security reason, we MUST make a copy.
  model_size_ = model_content->get_shared_memory()->size;

  auto shared_region = base::WritableSharedMemoryRegion::ConvertToReadOnly(
      mojo::UnwrapWritableSharedMemoryRegion(
          std::move(model_content->get_shared_memory()->buffer_handle)));
  auto shared_mapping = shared_region.Map();
  if (!shared_region.IsValid() || !shared_mapping.IsValid()) {
    std::move(callback).Run(model_loader::mojom::LoadModelResult::kUnknownError,
                            mojo::NullRemote(), nullptr);
    return false;
  }
  model_content_.reset(new char[model_size_]);
  memcpy(model_content_.get(), shared_mapping.GetMemoryAs<char>(), model_size_);
  model_ = tflite::FlatBufferModel::VerifyAndBuildFromBuffer(
      model_content_.get(), model_size_);

  return true;
}

void WebPlatformModelImpl::CollectTensorInformation(
    const std::vector<int>& tensor_indices_in_model,
    base::flat_map<std::string, model_loader::mojom::TensorInfoPtr>&
        io_tensor_info) {
  for (auto tensor_idx : tensor_indices_in_model) {
    std::string tensor_name(interpreter_->tensor(tensor_idx)->name);
    TensorInfo tensor_info;
    tensor_info.size = interpreter_->tensor(tensor_idx)->bytes;
    tensor_info.data_type = interpreter_->tensor(tensor_idx)->type;
    name_to_tensor_info_[tensor_name] = tensor_info;

    auto mojo_tensor_info = model_loader::mojom::TensorInfo::New();
    mojo_tensor_info->byte_size = tensor_info.size;
    mojo_tensor_info->data_type =
        ConvertTfLiteTypeToMojo(tensor_info.data_type);
    mojo_tensor_info->dimensions =
        ConvertTfLiteDimensions(interpreter_->tensor(tensor_idx)->dims);

    io_tensor_info[tensor_name] = std::move(mojo_tensor_info);
  }
}

bool WebPlatformModelImpl::Load(
    mojo_base::mojom::BigBufferPtr model_content,
    WebPlatformModelLoaderImpl::LoadCallback& callback) {
  RequestMetrics request_metrics(kModelName, "Load");
  request_metrics.StartRecordingPerformanceMetrics();

  if (model_content->is_invalid_buffer()) {
    std::move(callback).Run(model_loader::mojom::LoadModelResult::kUnknownError,
                            mojo::NullRemote(), nullptr);
    request_metrics.RecordRequestEvent(
        MetricEventForLoad::kInvalidInputBigBuffer);
    return false;
  } else if (model_content->is_bytes()) {
    BuildModelFromBytes(model_content);
  } else if (model_content->is_shared_memory()) {
    if (!BuildModelFromSharedBuffer(model_content, callback)) {
      // The `callback` has already called with appropriate error messages in
      // `BuildModelFromSharedBuffer`.
      request_metrics.RecordRequestEvent(
          MetricEventForLoad::kInvalidSharedBuffer);
      return false;
    }
  } else {
    LOG(FATAL) << "Unknown type of input BigBuffer. Please check if "
                  "mojom::BigBuffer has been extended.";
    request_metrics.RecordRequestEvent(
        MetricEventForLoad::kUnknownTypeOfInputBigBuffer);
  }

  if (model_ == nullptr) {
    std::move(callback).Run(model_loader::mojom::LoadModelResult::kInvalidModel,
                            mojo::NullRemote(), nullptr);
    brillo::MessageLoop::current()->BreakLoop();
    request_metrics.RecordRequestEvent(MetricEventForLoad::kBuildModelFailed);
    return false;
  }

  // Sets up the interpreter.
  resolver_ = std::make_unique<tflite::ops::builtin::BuiltinOpResolver>();
  interpreter_ = std::make_unique<tflite::Interpreter>();

  const TfLiteStatus resolve_status =
      tflite::InterpreterBuilder(*model_, *resolver_)(&interpreter_);
  if (resolve_status != kTfLiteOk || !interpreter_) {
    std::move(callback).Run(model_loader::mojom::LoadModelResult::kInvalidModel,
                            mojo::NullRemote(), nullptr);
    request_metrics.RecordRequestEvent(
        MetricEventForLoad::kInterpretModelFailed);
    return false;
  }

  // If you want to set up delegate (e.g. NNAPI), do it here.

  // Allocates the tensors.
  // Notice that maybe we can move this to the `compute()` function.
  if (interpreter_->AllocateTensors() != kTfLiteOk) {
    std::move(callback).Run(model_loader::mojom::LoadModelResult::kUnknownError,
                            mojo::NullRemote(), nullptr);
    request_metrics.RecordRequestEvent(
        MetricEventForLoad::kAllocateTensorFailed);
    return false;
  }

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(MetricEventForLoad::kSuccess);
  return true;
}

model_loader::mojom::ModelInfoPtr WebPlatformModelImpl::GetModelInfo() {
  auto model_info = model_loader::mojom::ModelInfo::New();
  CollectTensorInformation(interpreter_->inputs(),
                           model_info->input_tensor_info);
  CollectTensorInformation(interpreter_->outputs(),
                           model_info->output_tensor_info);
  return model_info;
}

void WebPlatformModelImpl::Compute(
    const base::flat_map<std::string, std::vector<uint8_t>>& name_tensors,
    ComputeCallback callback) {
  RequestMetrics request_metrics(kModelName, "Compute");
  request_metrics.StartRecordingPerformanceMetrics();

  // Sets up the input.
  // Checks if the number of input tensors is correct.
  if (interpreter_->inputs().size() != name_tensors.size()) {
    std::move(callback).Run(
        model_loader::mojom::ComputeResult::kIncorrectNumberOfInputs,
        std::nullopt);
    request_metrics.RecordRequestEvent(
        MetricEventForCompute::kIncorrectNumberOfInputs);
    return;
  }

  // More self-consistency check on the input tensors.
  for (auto tensor_idx : interpreter_->inputs()) {
    std::string tensor_name(interpreter_->tensor(tensor_idx)->name);
    auto iter = name_tensors.find(tensor_name);
    if (iter == name_tensors.end()) {
      std::move(callback).Run(model_loader::mojom::ComputeResult::kMissingInput,
                              std::nullopt);
      request_metrics.RecordRequestEvent(MetricEventForCompute::kMissingInput);
      return;
    }
    if (iter->second.size() != interpreter_->tensor(tensor_idx)->bytes) {
      std::move(callback).Run(
          model_loader::mojom::ComputeResult::kInvalidInputBufferSize,
          std::nullopt);
      request_metrics.RecordRequestEvent(
          MetricEventForCompute::kInvalidInputBufferSize);
      return;
    }
  }

  // Fills the buffer.
  for (auto tensor_idx : interpreter_->inputs()) {
    std::string tensor_name(interpreter_->tensor(tensor_idx)->name);
    auto iter = name_tensors.find(tensor_name);
    memcpy(interpreter_->tensor(tensor_idx)->data.raw, iter->second.data(),
           iter->second.size());
  }

  // Does the computation.
  if (interpreter_->Invoke() != kTfLiteOk) {
    std::move(callback).Run(model_loader::mojom::ComputeResult::kUnknownError,
                            std::nullopt);
    request_metrics.RecordRequestEvent(MetricEventForCompute::kFailToCompute);
    return;
  }

  // Fills the buffer with output.
  base::flat_map<std::string, std::vector<uint8_t>> output_buffer_infos;
  for (auto tensor_idx : interpreter_->outputs()) {
    std::vector<uint8_t> tensor(
        static_cast<size_t>(interpreter_->tensor(tensor_idx)->bytes));
    memcpy(tensor.data(), interpreter_->tensor(tensor_idx)->data.raw,
           interpreter_->tensor(tensor_idx)->bytes);
    output_buffer_infos[interpreter_->tensor(tensor_idx)->name] =
        std::move(tensor);
  }

  std::move(callback).Run(model_loader::mojom::ComputeResult::kOk,
                          std::move(output_buffer_infos));

  request_metrics.FinishRecordingPerformanceMetrics();
  request_metrics.RecordRequestEvent(MetricEventForCompute::kSuccess);
}

}  // namespace ml
