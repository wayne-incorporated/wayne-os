/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/transform.h"

namespace cros {

std::vector<float> TextureSpaceFromNdc() {
  // clang-format off
  return { 0.5f,  0.0f,  0.0f,  0.0f,
           0.0f,  0.5f,  0.0f,  0.0f,
           0.0f,  0.0f,  1.0f,  0.0f,
           0.5f,  0.5f,  0.0f,  1.0f };
  // clang-format on
}

}  // namespace cros
