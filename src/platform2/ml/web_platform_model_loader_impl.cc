// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/web_platform_model_loader_impl.h"

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
#include "ml/web_platform_model_impl.h"

namespace ml {

namespace {

using model_loader::mojom::CreateModelLoaderOptionsPtr;
using model_loader::mojom::ModelLoader;

}  // namespace

WebPlatformModelLoaderImpl* WebPlatformModelLoaderImpl::Create(
    mojo::PendingReceiver<ModelLoader> receiver,
    CreateModelLoaderOptionsPtr options) {
  // TODO(honglinyu): in the first version, `options.threads` is unused. We need
  // to make it meaningful.

  auto model_loaded_impl =
      new WebPlatformModelLoaderImpl(std::move(receiver), std::move(options));
  // In production, `model_loaded_impl` is intentionally leaked, because this
  // model runs in its own process and the model's memory is freed when the
  // process exits. However, when being tested with ASAN, this memory leak
  // causes an error. Therefore, we annotate it as an intentional leak.
  ANNOTATE_LEAKING_OBJECT_PTR(model_loaded_impl);

  //  Sets the default disconnection handler which,
  //    - resets the `receiver_`.
  //    - quits the message loop if no model is connected.
  //  Note that it should NOT delete itself.
  model_loaded_impl->receiver_.set_disconnect_handler(
      base::BindOnce(&WebPlatformModelLoaderImpl::DefaultDisconnectHandler,
                     base::Unretained(model_loaded_impl)));

  return model_loaded_impl;
}

WebPlatformModelLoaderImpl::WebPlatformModelLoaderImpl(
    mojo::PendingReceiver<ModelLoader> receiver,
    CreateModelLoaderOptionsPtr options)
    : num_of_connected_models_(0), receiver_(this, std::move(receiver)) {
  // TODO(honglinyu): makes use of `options->num_threads`.
  DETACH_FROM_SEQUENCE(sequence_checker_);
}

bool WebPlatformModelLoaderImpl::IsValid() const {
  return receiver_.is_bound();
}

void WebPlatformModelLoaderImpl::RegisterModel() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  ++num_of_connected_models_;
}

int WebPlatformModelLoaderImpl::UnregisterModel() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
  return --num_of_connected_models_;
}

void WebPlatformModelLoaderImpl::Load(
    mojo_base::mojom::BigBufferPtr model_content, LoadCallback callback) {
  WebPlatformModelImpl::Create(std::move(model_content), std::move(callback),
                               this);
}

// Note that the disconnect handler should NOT delete itself because the
// `WebPlatformModelImpl` objects have reference pointers to it.
void WebPlatformModelLoaderImpl::DefaultDisconnectHandler() {
  receiver_.reset();
  if (num_of_connected_models_ == 0) {
    brillo::MessageLoop::current()->BreakLoop();
  }
}

}  // namespace ml
