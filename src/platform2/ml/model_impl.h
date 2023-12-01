// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_MODEL_IMPL_H_
#define ML_MODEL_IMPL_H_

#include <list>
#include <memory>
#include <string>

#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <tensorflow/lite/model.h>

#include "ml/graph_executor_impl.h"
#include "ml/model_delegate.h"
#include "ml/mojom/model.mojom.h"

namespace ml {

// Holds a ModelDelegate ptr and calls its CreateGraphExecutorDelegate to
// produce GraphExecutorDelegate that can run the graph, and uses
// GraphExecutorDelegate to produce GraphExecutorImpl that can response to mojo
// calls to GraphExecutor interface.
//
// All GraphExecutorImpls created by a ModelImpl reference its model definition
// (and hence may not outlive the ModelImpl). Multiple such GraphExecutorImpls
// may be used concurrently from different sequences.
//
// Example usage:
//  std::unique_ptr<tflite::FlatBufferModel> tflite_model = xxx;
//  const std::string metrics_model_name = xxx;
//  mojo::Remote<Model> model;
//  ModelImpl::Create(
//      std::make_unique<ModelDelegate>(
//          required_input, required_output, std::move(model),
//          std::move(tflite_model), metrics_model_name),
//      model.BindNewPipeAndPassReceiver());
class ModelImpl : public chromeos::machine_learning::mojom::Model {
 public:
  // Takes ownership of `model_delegate` and creates an instance bound to
  // `receiver`.
  //
  // The RAM of the returned model is not owned by the caller. The model object
  // will be deleted when the corresponding mojo connection is closed.
  static ModelImpl* Create(
      std::unique_ptr<ModelDelegate> model_delegate,
      mojo::PendingReceiver<chromeos::machine_learning::mojom::Model> receiver);

  int num_graph_executors_for_testing() const;

 private:
  // Constructor is private, call `Create` to create objects.
  ModelImpl(
      std::unique_ptr<ModelDelegate> model_delegate,
      mojo::PendingReceiver<chromeos::machine_learning::mojom::Model> receiver);
  ModelImpl(const ModelImpl&) = delete;
  ModelImpl& operator=(const ModelImpl&) = delete;

  void set_disconnect_handler(base::OnceClosure disconnect_handler);

  // chromeos::machine_learning::mojom::Model:
  void REMOVED_0(mojo::PendingReceiver<
                     chromeos::machine_learning::mojom::GraphExecutor> receiver,
                 CreateGraphExecutorCallback callback) override;
  void CreateGraphExecutor(
      chromeos::machine_learning::mojom::GraphExecutorOptionsPtr options,
      mojo::PendingReceiver<chromeos::machine_learning::mojom::GraphExecutor>
          receiver,
      CreateGraphExecutorCallback callback) override;

  // Remove a graph executor from our hosted set.
  void EraseGraphExecutor(std::list<GraphExecutorImpl>::const_iterator it);

  // The delegate that actually calls TFLite.
  std::unique_ptr<ModelDelegate> model_delegate_;
  mojo::Receiver<chromeos::machine_learning::mojom::Model> receiver_;

  // Emulate a strongly bound receiver set: hold a set of GraphExecutors,
  // specific elements of which are erased on connection closure.
  //
  // That is, when a pipe to a GraphExecutorImpl closes, that object is removed
  // from this set (by its binding disconnection handler). Further, when a
  // ModelImpl is destroyed, its entire collection of GraphExecutorImpls is also
  // destroyed.
  std::list<GraphExecutorImpl> graph_executors_;
};

}  // namespace ml

#endif  // ML_MODEL_IMPL_H_
