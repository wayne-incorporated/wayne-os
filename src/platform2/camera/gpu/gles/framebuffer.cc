/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/framebuffer.h"

#include <utility>

#include "cros-camera/common.h"
#include "gpu/gles/utils.h"

namespace cros {

Framebuffer::Framebuffer() {
  glGenFramebuffers(1, &id_);
  if (id_ == 0) {
    LOGF(ERROR) << "Failed to generate framebuffer";
  }
}

Framebuffer::Framebuffer(Framebuffer&& other) {
  *this = std::move(other);
}

Framebuffer& Framebuffer::operator=(Framebuffer&& other) {
  if (this != &other) {
    Invalidate();
    id_ = other.id_;
    other.id_ = 0;
  }
  return *this;
}

Framebuffer::~Framebuffer() {
  Invalidate();
}

bool Framebuffer::Bind() const {
  if (!IsValid()) {
    LOGF(ERROR) << "Attempting to bind an invalid framebuffer";
    return false;
  }
  glBindFramebuffer(GL_FRAMEBUFFER, id_);
  GLenum error = glGetError();
  if (error != GL_NO_ERROR) {
    LOGF(ERROR) << "Failed to bind framebuffer: " << GlGetErrorString(error);
    return false;
  }
  return true;
}

void Framebuffer::Invalidate() {
  if (IsValid()) {
    glDeleteFramebuffers(1, &id_);
  }
  id_ = 0;
}

bool Framebuffer::Attach(GLenum attachment, const Texture2D& texture) {
  if (!IsValid()) {
    LOGF(ERROR) << "Cannot attach a texture to an invalid framebuffer";
    return false;
  }

  CHECK_EQ(texture.target(), GL_TEXTURE_2D)
      << ": |texture| must have target GL_TEXTURE_2D";

  glFramebufferTexture2D(GL_DRAW_FRAMEBUFFER, attachment, texture.target(),
                         texture.handle(), 0);
  if (glGetError() != GL_NO_ERROR) {
    LOGF(ERROR) << "Failed to attach draw framebuffer";
    return false;
  }
  glFramebufferTexture2D(GL_READ_FRAMEBUFFER, attachment, texture.target(),
                         texture.handle(), 0);
  if (glGetError() != GL_NO_ERROR) {
    LOGF(ERROR) << "Failed to attach read framebuffer";
    return false;
  }
  return true;
}

}  // namespace cros
