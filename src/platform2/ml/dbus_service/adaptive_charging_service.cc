// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/dbus_service/adaptive_charging_service.h"

#include <utility>

#include "ml/tensor_view.h"

namespace ml {
namespace {

using ::chromeos::machine_learning::mojom::BuiltinModelId;
using ::chromeos::machine_learning::mojom::TensorPtr;

constexpr char kPreprocessorFileName[] =
    "mlservice-model-adaptive_charging-20230314-preprocessor.pb";

}  // namespace

AdaptiveChargingService::AdaptiveChargingService(
    std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object)
    : org::chromium::MachineLearning::AdaptiveChargingAdaptor(this),
      dbus_object_(std::move(dbus_object)),
      tf_model_graph_executor_(new TfModelGraphExecutor(
          BuiltinModelId::ADAPTIVE_CHARGING_20230314, kPreprocessorFileName)) {}

AdaptiveChargingService::~AdaptiveChargingService() = default;

void AdaptiveChargingService::RegisterAsync(
    brillo::dbus_utils::AsyncEventSequencer::CompletionAction
        completion_callback) {
  RegisterWithDBusObject(dbus_object_.get());
  dbus_object_->RegisterAsync(std::move(completion_callback));
}

void AdaptiveChargingService::RequestAdaptiveChargingDecision(
    std::unique_ptr<
        brillo::dbus_utils::DBusMethodResponse<bool, std::vector<double>>>
        response,
    const std::vector<uint8_t>& serialized_example_proto) {
  if (!tf_model_graph_executor_->Ready()) {
    LOG(ERROR) << "TfModelGraphExecutor is not properly initialized.";
    response->Return(false, std::vector<double>());
    return;
  }

  assist_ranker::RankerExample example;
  if (!example.ParseFromArray(serialized_example_proto.data(),
                              serialized_example_proto.size())) {
    LOG(ERROR) << "Failed to parse serialized_example_proto";
    response->Return(false, std::vector<double>());
    return;
  }

  std::vector<TensorPtr> output_tensors;
  if (!tf_model_graph_executor_->Execute(true /*clear_other_features*/,
                                         &example, &output_tensors)) {
    LOG(ERROR) << "TfModelGraphExecutor::Execute failed!";
    response->Return(false, std::vector<double>());
    return;
  }

  DCHECK_EQ(output_tensors.size(), 1u);
  // Extracts output values and returns with dbus response.
  const TensorView<double> out_tensor_view(output_tensors[0]);
  DCHECK(out_tensor_view.IsValidType());
  DCHECK(out_tensor_view.IsValidFormat());

  response->Return(true, out_tensor_view.GetValues());
}

}  // namespace ml
