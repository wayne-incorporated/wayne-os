// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/graph_executor_impl.h"

#include <optional>
#include <utility>

#include <base/stl_util.h>

#include "ml/mojom/tensor.mojom.h"

namespace ml {

namespace {

using ::chromeos::machine_learning::mojom::ExecuteResult;
using ::chromeos::machine_learning::mojom::GraphExecutor;
using ::chromeos::machine_learning::mojom::TensorPtr;

}  // namespace

GraphExecutorImpl::GraphExecutorImpl(
    std::unique_ptr<GraphExecutorDelegate> graph_executor_delegate,
    mojo::PendingReceiver<GraphExecutor> receiver)
    : graph_executor_delegate_(std::move(graph_executor_delegate)),
      receiver_(this, std::move(receiver)) {}

void GraphExecutorImpl::set_disconnect_handler(
    base::OnceClosure disconnect_handler) {
  receiver_.set_disconnect_handler(std::move(disconnect_handler));
}

void GraphExecutorImpl::Execute(base::flat_map<std::string, TensorPtr> tensors,
                                const std::vector<std::string>& outputs,
                                ExecuteCallback callback) {
  std::vector<chromeos::machine_learning::mojom::TensorPtr> output_tensors;
  auto result = graph_executor_delegate_->Execute(std::move(tensors), outputs,
                                                  output_tensors);

  if (result != ExecuteResult::OK) {
    std::move(callback).Run(result, std::nullopt);
  } else {
    std::move(callback).Run(result, std::move(output_tensors));
  }
}

}  // namespace ml
