// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/model_metadata.h"

namespace ml {

using ::chromeos::machine_learning::mojom::BuiltinModelId;

std::map<BuiltinModelId, BuiltinModelMetadata> GetBuiltinModelMetadata() {
  return {
      {
          BuiltinModelId::TEST_MODEL,
          {
              BuiltinModelId::TEST_MODEL,
              "mlservice-model-test_add-20180914.tflite",
              {{"x", 1}, {"y", 2}},
              {{"z", 0}},
              "TestModel",
          },
      },
      {
          BuiltinModelId::SMART_DIM_20190521,
          {
              BuiltinModelId::SMART_DIM_20190521,
              "mlservice-model-smart_dim-20190521-v3.tflite",
              {{"input", 3}},
              {{"output", 4}},
              "SmartDimModel",
          },
      },
      {
          BuiltinModelId::ADAPTIVE_CHARGING_20230314,
          {
              BuiltinModelId::ADAPTIVE_CHARGING_20230314,
              "mlservice-model-adaptive_charging-20230314.tflite",
              {{"input", 0}},
              {{"output", 13}},
              "AdaptiveChargingModel",
          },
      },
      {
          BuiltinModelId::PONCHO_PALM_REJECTION_20230213,
          {
              BuiltinModelId::PONCHO_PALM_REJECTION_20230213,
              "mlservice-model-poncho_palm_rejection-test_quantized_20230213."
              "tflite",
              {{"input", 0}},
              {{"output", 23}},
              "PonchoPalmRejectionModel",
          },
      },
  };
}

}  // namespace ml
