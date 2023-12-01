/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/state_guard.h"

#include "gpu/gles/get.h"

namespace cros {

FramebufferGuard::FramebufferGuard()
    : draw_fbo_(Get<GLuint>(GL_DRAW_FRAMEBUFFER_BINDING)),
      read_fbo_(Get<GLuint>(GL_READ_FRAMEBUFFER_BINDING)) {}

FramebufferGuard::~FramebufferGuard() {
  glBindFramebuffer(GL_DRAW_FRAMEBUFFER, draw_fbo_);
  glBindFramebuffer(GL_READ_FRAMEBUFFER, read_fbo_);
}

ViewportGuard::ViewportGuard() : viewport_(GetIntArray<4>(GL_VIEWPORT)) {}

ViewportGuard::~ViewportGuard() {
  glViewport(viewport_[0], viewport_[1], viewport_[2], viewport_[3]);
}

ProgramGuard::ProgramGuard() : program_(Get<GLuint>(GL_CURRENT_PROGRAM)) {}

ProgramGuard::~ProgramGuard() {
  glUseProgram(program_);
}

VertexArrayGuard::VertexArrayGuard()
    : vertex_array_(Get<GLuint>(GL_VERTEX_ARRAY_BINDING)) {}

VertexArrayGuard::~VertexArrayGuard() {
  glBindVertexArray(vertex_array_);
}

}  // namespace cros
