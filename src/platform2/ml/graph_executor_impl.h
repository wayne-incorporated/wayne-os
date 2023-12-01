// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_GRAPH_EXECUTOR_IMPL_H_
#define ML_GRAPH_EXECUTOR_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include <base/containers/flat_map.h>
#include <base/functional/callback_forward.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>

#include "ml/graph_executor_delegate.h"
#include "ml/mojom/graph_executor.mojom.h"

namespace ml {

// Allows execution of TensorFlow lite graphs using input / output specified
// with Mojo types.
//
// Holds as little state as possible (with the remainder living in the parent
// Model object and shared between all sibling GraphExecutors). Hence, a
// GraphExecutor becomes invalid when its parent Model object is destroyed.
//
// A given GraphExecutorImpl may not be used concurrently from different
// sequences.
// Example usage:
//  auto interpreter = std::make_unique<tflite::Interpreter>();
//  const std::string metrics_model_name = xxx;
//  mojo::Remote<GraphExecutor> graph_executor;
//  const GraphExecutorImpl graph_executor_impl(
//      std::make_unique<GraphExecutorDelegate>(
//          input_names, output_names, std::move(graph_executor_delegate),
//          metrics_model_name),
//      graph_executor.BindNewPipeAndPassReceiver());
class GraphExecutorImpl
    : public chromeos::machine_learning::mojom::GraphExecutor {
 public:
  // Takes ownership of `graph_executor_delegate` to do the actual work of
  // calling TFlite, and creates an instance bound to `receiver`.
  GraphExecutorImpl(
      std::unique_ptr<GraphExecutorDelegate> graph_executor_delegate,
      mojo::PendingReceiver<chromeos::machine_learning::mojom::GraphExecutor>
          receiver);
  GraphExecutorImpl(const GraphExecutorImpl&) = delete;
  GraphExecutorImpl& operator=(const GraphExecutorImpl&) = delete;

  void set_disconnect_handler(base::OnceClosure disconnect_handler);

 private:
  // chromeos::machine_learning::mojom::GraphExecutor:
  void Execute(
      base::flat_map<std::string, chromeos::machine_learning::mojom::TensorPtr>
          inputs,
      const std::vector<std::string>& output_names,
      ExecuteCallback callback);

  // The delegate that actually runs TFLite graph.
  std::unique_ptr<GraphExecutorDelegate> graph_executor_delegate_;
  mojo::Receiver<chromeos::machine_learning::mojom::GraphExecutor> receiver_;
};

}  // namespace ml

#endif  // ML_GRAPH_EXECUTOR_IMPL_H_
