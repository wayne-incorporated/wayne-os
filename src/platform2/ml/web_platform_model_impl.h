// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_WEB_PLATFORM_MODEL_IMPL_H_
#define ML_WEB_PLATFORM_MODEL_IMPL_H_

#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <tensorflow/lite/kernels/register.h>
#include <tensorflow/lite/context.h>
#include <tensorflow/lite/model.h>
#include <tensorflow/lite/delegates/nnapi/nnapi_delegate.h>
#include <tensorflow/lite/interpreter.h>

#include "ml/mojom/web_platform_model.mojom.h"
#include "ml/web_platform_model_loader_impl.h"

namespace ml {

class WebPlatformModelImpl : public model_loader::mojom::Model {
 public:
  static void Create(mojo_base::mojom::BigBufferPtr model_content,
                     WebPlatformModelLoaderImpl::LoadCallback callback,
                     WebPlatformModelLoaderImpl* loader);

 private:
  struct TensorInfo {
    int index;
    // Size in bytes.
    size_t size;
    TfLiteType data_type;
  };

  // Constructor is private, call `Create` to create objects.
  WebPlatformModelImpl(
      mojo::PendingReceiver<model_loader::mojom::Model> receiver,
      WebPlatformModelLoaderImpl* loader);
  WebPlatformModelImpl(const WebPlatformModelImpl&) = delete;
  WebPlatformModelImpl& operator=(const WebPlatformModelImpl&) = delete;

  void DefaultDisconnectHandler();

  // Builds the model from bytes or shared buffer, depending on the type of
  // input `model_content` from clients.
  // These two are helper functions used by `Load()` to improve readability.
  // Function `BuildModelFromSharedBuffer` returns true if the input
  // `model_content` is valid, otherwise returns false. Notice that `model_` can
  // still be null after these functions succeed (e.g. the model format is
  // invalid). This must be checked in the `Load` function.
  void BuildModelFromBytes(mojo_base::mojom::BigBufferPtr& model_content);
  // Invokes callback in case of any errors, but does not invoke the callback in
  // case of success.
  bool BuildModelFromSharedBuffer(
      mojo_base::mojom::BigBufferPtr& model_content,
      WebPlatformModelLoaderImpl::LoadCallback& callback);

  // Helper function to collect input/output tensor information from TfLite
  // model. Used by the `Load()` function.
  void CollectTensorInformation(
      const std::vector<int>& tensor_indices_in_model,
      base::flat_map<std::string, model_loader::mojom::TensorInfoPtr>&
          io_tensor_info);

  // A helper function to load the model and build interpreters.
  // Returns true if succeeded and the `callback` will be untouched.
  // Otherwise, returns false and the `callback` is called.
  bool Load(mojo_base::mojom::BigBufferPtr model_content,
            WebPlatformModelLoaderImpl::LoadCallback& callback);

  model_loader::mojom::ModelInfoPtr GetModelInfo();

  // model_loader::mojom::Model:
  void Compute(
      const base::flat_map<std::string, std::vector<uint8_t>>& name_tensors,
      ComputeCallback callback) override;

  // Used to contain the model content when,
  //   - It is passed in by "shared buffer". In this case, for security reason,
  //     we MUST make a copy.
  //   - Or when it is passed in by "bytes" but is not aligned. In this case,
  //     we mast make it aligned to make sure TfLite works properly.
  std::unique_ptr<char[]> model_content_;
  uint32_t model_size_;

  // Used to hold the model content when it is passed in by "bytes" and is
  // aligned.
  mojo_base::mojom::BigBufferPtr model_big_buffer_ptr_;

  std::unique_ptr<tflite::FlatBufferModel> model_;
  std::unique_ptr<tflite::ops::builtin::BuiltinOpResolver> resolver_;
  std::unique_ptr<tflite::Interpreter> interpreter_;

  // Model information.
  std::unordered_map<std::string, TensorInfo> name_to_tensor_info_;

  // An observer to the loader object. The loader object will never be
  // destroyed.
  WebPlatformModelLoaderImpl* const loader_;

  mojo::Receiver<model_loader::mojom::Model> receiver_;
};

}  // namespace ml

#endif  // ML_WEB_PLATFORM_MODEL_IMPL_H_
