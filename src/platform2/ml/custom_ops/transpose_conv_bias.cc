// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "ml/custom_ops/transpose_conv_bias.h"

namespace ml {
namespace custom_ops {

TfLiteRegistration* RegisterConvolution2DTransposeBias() {
  // This op is already implemented by the XNNPACK (and GPU) delegate, so there
  // is no need to provide a fallback CPU implementation here. It's also not
  // implemented by the NNAPI delegate, but we don't allow partitioned execution
  // anyway.
  static TfLiteRegistration reg = {nullptr, nullptr, nullptr, nullptr};
  return &reg;
}

}  // namespace custom_ops
}  // namespace ml
