/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_TEST_SUPPORT_GL_TEST_FIXTURE_H_
#define CAMERA_GPU_TEST_SUPPORT_GL_TEST_FIXTURE_H_

#include <memory>

#include <hardware/gralloc.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/common.h"
#include "gpu/egl/egl_context.h"
#include "gpu/egl/utils.h"
#include "gpu/gles/utils.h"

namespace cros {

// Fills |buffer| with a gradient test pattern that transitions (0, 0, 0) from
// the top left cornet to (255, 255, 0) on the bottom-right corner.
void FillTestPattern(buffer_handle_t buffer);

// Gets the RGBA pixel value at (|x|, |y|) on an image of dimension
// (|width|, |height|) with pixel values filled by FillTestPattern().
std::array<uint8_t, 4> GetTestRgbaColor(int x, int y, int width, int height);

// Gets the YUV pixel value at (|x|, |y|) on an image of dimension
// (|width|, |height|) with pixel values filled by FillTestPattern().
std::array<uint8_t, 3> GetTestYuvColor(int x, int y, int width, int height);

// Gets the YUYV pixel value at (|x|, |y|) on an image of dimension
// (|width|, |height|) with pixel values filled by FillTestPattern().
// Here, one pixel corresponds to one (YU, YV) pair, which amounts to 4 bytes.
std::array<uint8_t, 4> GetTestYuyvColor(int x, int y, int width, int height);

class GlTestFixture {
 public:
  GlTestFixture();
  ~GlTestFixture() = default;

  void DumpInfo() const;

 private:
  std::unique_ptr<EglContext> egl_context_;
};

}  // namespace cros

#endif  // CAMERA_GPU_TEST_SUPPORT_GL_TEST_FIXTURE_H_
