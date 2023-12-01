// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_DBUS_SERVICE_ADAPTIVE_CHARGING_SERVICE_H_
#define ML_DBUS_SERVICE_ADAPTIVE_CHARGING_SERVICE_H_

#include <memory>
#include <string>
#include <vector>

#include "dbus_adaptors/org.chromium.MachineLearning.AdaptiveCharging.h"
#include "ml/dbus_service/tf_model_graph_executor.h"

namespace ml {

// Implementation of the adaptive charging dbus interface.
class AdaptiveChargingService
    : public org::chromium::MachineLearning::AdaptiveChargingAdaptor,
      public org::chromium::MachineLearning::AdaptiveChargingInterface {
 public:
  explicit AdaptiveChargingService(
      std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object);
  AdaptiveChargingService(const AdaptiveChargingService&) = delete;
  AdaptiveChargingService& operator=(const AdaptiveChargingService&) = delete;
  ~AdaptiveChargingService();

  // Register DBus object and interfaces.
  void RegisterAsync(brillo::dbus_utils::AsyncEventSequencer::CompletionAction
                         completion_callback);

  // org::chromium::MachineLearning::AdaptiveCharging: (see
  // dbus_bindings/org.chromium.MachineLearning.AdaptiveCharging.xml).
  void RequestAdaptiveChargingDecision(
      std::unique_ptr<
          brillo::dbus_utils::DBusMethodResponse<bool, std::vector<double>>>
          response,
      const std::vector<uint8_t>& serialized_example_proto) override;

 private:
  const std::unique_ptr<brillo::dbus_utils::DBusObject> dbus_object_;
  const std::unique_ptr<TfModelGraphExecutor> tf_model_graph_executor_;
};

}  // namespace ml

#endif  // ML_DBUS_SERVICE_ADAPTIVE_CHARGING_SERVICE_H_
