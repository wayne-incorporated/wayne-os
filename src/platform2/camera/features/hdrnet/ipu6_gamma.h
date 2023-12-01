/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_HDRNET_IPU6_GAMMA_H_
#define CAMERA_FEATURES_HDRNET_IPU6_GAMMA_H_

#include <cstdint>

#include "gpu/gles/texture_2d.h"

namespace cros::intel_ipu6 {

Texture2D CreateGammaLutTexture();
Texture2D CreateInverseGammaLutTexture();

}  // namespace cros::intel_ipu6

#endif  // CAMERA_FEATURES_HDRNET_IPU6_GAMMA_H_
