// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_WEB_PLATFORM_MODEL_LOADER_IMPL_H_
#define ML_WEB_PLATFORM_MODEL_LOADER_IMPL_H_

#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <base/sequence_checker.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <tensorflow/lite/kernels/register.h>
#include <tensorflow/lite/context.h>
#include <tensorflow/lite/model.h>
#include <tensorflow/lite/delegates/nnapi/nnapi_delegate.h>
#include <tensorflow/lite/interpreter.h>

#include "ml/mojom/web_platform_model.mojom.h"

namespace ml {

class WebPlatformModelLoaderImpl : public model_loader::mojom::ModelLoader {
 public:
  static WebPlatformModelLoaderImpl* Create(
      mojo::PendingReceiver<model_loader::mojom::ModelLoader> receiver,
      model_loader::mojom::CreateModelLoaderOptionsPtr options);

  // Returns true if `receiver_` is bound, otherwise, returns false.
  // This is used by the mojo disconnect handler of `WebPlatformModelImpl` to
  // see if they should break the message loop.
  bool IsValid() const;

  // Increases `num_of_connected_models_` by 1.
  void RegisterModel();
  // Decreases `num_of_connected_models_` by 1. Returns the new value.
  int UnregisterModel();

 private:
  // Constructor is private, call `Create` to create objects.
  WebPlatformModelLoaderImpl(
      mojo::PendingReceiver<model_loader::mojom::ModelLoader> receiver,
      model_loader::mojom::CreateModelLoaderOptionsPtr options);
  WebPlatformModelLoaderImpl(const WebPlatformModelLoaderImpl&) = delete;
  WebPlatformModelLoaderImpl& operator=(const WebPlatformModelLoaderImpl&) =
      delete;

  void DefaultDisconnectHandler();

  // model_loader::mojom::Model:
  void Load(mojo_base::mojom::BigBufferPtr model_content,
            LoadCallback callback) override;

  // Records the number of models that still have connected mojo pipes.
  int num_of_connected_models_;

  mojo::Receiver<model_loader::mojom::ModelLoader> receiver_;

  // Used for guarding `num_of_connected_models_`.
  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace ml

#endif  // ML_WEB_PLATFORM_MODEL_LOADER_IMPL_H_
