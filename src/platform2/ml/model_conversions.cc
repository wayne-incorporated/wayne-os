// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/model_conversions.h"

#include <base/check.h>
#include <base/notreached.h>

using chromeos::machine_learning::mojom::GpuDelegateApi;

namespace ml {

GpuDelegateApi GpuDelegateApiFromProto(TfliteGpuDelegateApi gpu_delegate_api) {
  switch (gpu_delegate_api) {
    case TfliteGpuDelegateApi::GPU_DELEGATE_API_UNKNOWN:
      return GpuDelegateApi::UNKNOWN;
    case TfliteGpuDelegateApi::GPU_DELEGATE_API_OPENGL:
      return GpuDelegateApi::OPENGL;
    case TfliteGpuDelegateApi::GPU_DELEGATE_API_OPENCL:
      return GpuDelegateApi::OPENCL;
    default:
      LOG(FATAL) << "Unknown GPU delegate API";
  }
  NOTREACHED();
  return GpuDelegateApi::UNKNOWN;
}

GpuDelegateApi GpuDelegateApiFromString(const std::string& string) {
  if (string == "OPENGL") {
    return GpuDelegateApi::OPENGL;
  }
  if (string == "OPENCL") {
    return GpuDelegateApi::OPENCL;
  }
  if (string == "UNKNOWN") {
    return GpuDelegateApi::UNKNOWN;
  }
  LOG(FATAL) << "Unknown GPU delegate API '" << string << "'";
  NOTREACHED();
  return GpuDelegateApi::UNKNOWN;
}

}  // namespace ml
