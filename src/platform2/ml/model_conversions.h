// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_MODEL_CONVERSIONS_H_
#define ML_MODEL_CONVERSIONS_H_

#include <string>

#include "ml/benchmark.pb.h"
#include "ml/mojom/model.mojom.h"

namespace ml {

chromeos::machine_learning::mojom::GpuDelegateApi GpuDelegateApiFromProto(
    TfliteGpuDelegateApi gpu_delegate_api);

chromeos::machine_learning::mojom::GpuDelegateApi GpuDelegateApiFromString(
    const std::string& string);

}  // namespace ml

#endif  // ML_MODEL_CONVERSIONS_H_
