// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_MODEL_METADATA_H_
#define ML_MODEL_METADATA_H_

#include <map>
#include <string>

#include "ml/mojom/model.mojom.h"

namespace ml {

// The information about one supported model.
struct BuiltinModelMetadata {
  chromeos::machine_learning::mojom::BuiltinModelId id;
  std::string model_file;

  // As accepted by the constructor of ModelImpl.
  std::map<std::string, int> required_inputs;
  std::map<std::string, int> required_outputs;

  // Used in naming the UMA metric histograms of the model. An example of the
  // names of the histograms is:
  //
  // MachineLearningService.`metrics_model_name`.ExecuteResult.CpuTimeMicrosec
  //
  // This variable must NOT be empty.
  std::string metrics_model_name;
};

// Returns a map from model ID to model metdata for each supported model.
std::map<chromeos::machine_learning::mojom::BuiltinModelId,
         BuiltinModelMetadata>
GetBuiltinModelMetadata();

}  // namespace ml

#endif  // ML_MODEL_METADATA_H_
