// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/model_impl.h"

#include <algorithm>
#include <utility>

#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/notreached.h>
#include <brillo/message_loops/message_loop.h>

#include "base/debug/leak_annotations.h"
#include "ml/graph_executor_delegate.h"
#include "ml/machine_learning_service_impl.h"

namespace ml {

using ::chromeos::machine_learning::mojom::CreateGraphExecutorResult;
using ::chromeos::machine_learning::mojom::GpuDelegateApi;
using ::chromeos::machine_learning::mojom::GraphExecutor;
using ::chromeos::machine_learning::mojom::GraphExecutorOptions;
using ::chromeos::machine_learning::mojom::GraphExecutorOptionsPtr;
using ::chromeos::machine_learning::mojom::Model;

ModelImpl* ModelImpl::Create(std::unique_ptr<ModelDelegate> model_delegate,
                             mojo::PendingReceiver<Model> receiver) {
  auto model_impl =
      new ModelImpl(std::move(model_delegate), std::move(receiver));
  // In production, `model_impl` is intentionally leaked, because this model
  // runs in its own process and the model's memory is freed when the process
  // exits. However, when being tested with ASAN, this memory leak causes an
  // error. Therefore, we annotate it as an intentional leak.
  ANNOTATE_LEAKING_OBJECT_PTR(model_impl);

  //  Set the disconnection handler to quit the message loop (i.e. exit the
  //  process) when the connection is gone, because this model is always run in
  //  a dedicated process.
  model_impl->receiver_.set_disconnect_handler(
      base::BindOnce(&brillo::MessageLoop::BreakLoop,
                     base::Unretained(brillo::MessageLoop::current())));

  return model_impl;
}

ModelImpl::ModelImpl(std::unique_ptr<ModelDelegate> model_delegate,
                     mojo::PendingReceiver<Model> receiver)
    : model_delegate_(std::move(model_delegate)),
      receiver_(this, std::move(receiver)) {}

void ModelImpl::set_disconnect_handler(base::OnceClosure disconnect_handler) {
  receiver_.set_disconnect_handler(std::move(disconnect_handler));
}

int ModelImpl::num_graph_executors_for_testing() const {
  return graph_executors_.size();
}

void ModelImpl::REMOVED_0(mojo::PendingReceiver<GraphExecutor> receiver,
                          CreateGraphExecutorCallback callback) {
  NOTIMPLEMENTED();
}

void ModelImpl::CreateGraphExecutor(
    GraphExecutorOptionsPtr options,
    mojo::PendingReceiver<GraphExecutor> receiver,
    CreateGraphExecutorCallback callback) {
  GraphExecutorDelegate* graph_executor_delegate;
  auto result = model_delegate_->CreateGraphExecutorDelegate(
      options->use_nnapi, options->use_gpu, options->gpu_delegate_api,
      &graph_executor_delegate);
  if (result != CreateGraphExecutorResult::OK) {
    std::move(callback).Run(result);
    return;
  }

  // Add graph executor and schedule its deletion on pipe closure.
  graph_executors_.emplace_front(
      std::unique_ptr<GraphExecutorDelegate>(graph_executor_delegate),
      std::move(receiver));
  graph_executors_.front().set_disconnect_handler(
      base::BindOnce(&ModelImpl::EraseGraphExecutor, base::Unretained(this),
                     graph_executors_.begin()));

  std::move(callback).Run(CreateGraphExecutorResult::OK);
}

void ModelImpl::EraseGraphExecutor(
    const std::list<GraphExecutorImpl>::const_iterator it) {
  graph_executors_.erase(it);
}

}  // namespace ml
