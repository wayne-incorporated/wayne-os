// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ML_CUSTOM_OPS_TRANSPOSE_CONV_BIAS_H_
#define ML_CUSTOM_OPS_TRANSPOSE_CONV_BIAS_H_

#include <tensorflow/lite/c/common.h>

namespace ml {
namespace custom_ops {

// Create registration for custom op "Convolution2DTransposeBias".
TfLiteRegistration* RegisterConvolution2DTransposeBias();

}  // namespace custom_ops
}  // namespace ml

#endif  // ML_CUSTOM_OPS_TRANSPOSE_CONV_BIAS_H_
