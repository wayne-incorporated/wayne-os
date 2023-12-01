/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_STATE_GUARD_H_
#define CAMERA_GPU_GLES_STATE_GUARD_H_

#include <array>

#include <GLES3/gl3.h>

// Various utility classes that store specific GL states on constructor, and
// restores the stored states on destruction.

namespace cros {

class FramebufferGuard {
 public:
  FramebufferGuard();
  ~FramebufferGuard();

 private:
  GLuint draw_fbo_;
  GLuint read_fbo_;
};

class ViewportGuard {
 public:
  ViewportGuard();
  ~ViewportGuard();

 private:
  std::array<GLint, 4> viewport_;
};

class ProgramGuard {
 public:
  ProgramGuard();
  ~ProgramGuard();

 private:
  GLuint program_;
};

class VertexArrayGuard {
 public:
  VertexArrayGuard();
  ~VertexArrayGuard();

 private:
  GLuint vertex_array_;
};

}  // namespace cros

#endif  // CAMERA_GPU_GLES_STATE_GUARD_H_
