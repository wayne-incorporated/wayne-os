/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_FRAMEBUFFER_H_
#define CAMERA_GPU_GLES_FRAMEBUFFER_H_

#include <GLES3/gl3.h>     // NOLINT
#include <GLES2/gl2ext.h>  // NOLINT

#include "gpu/gles/texture_2d.h"

namespace cros {

// A RAII helper class that encapsulates a GL framebuffer object (FBO).
class Framebuffer {
 public:
  // Creates a framebuffer object.
  Framebuffer();

  Framebuffer(const Framebuffer& other) = delete;
  Framebuffer(Framebuffer&& other);
  Framebuffer& operator=(const Framebuffer& other) = delete;
  Framebuffer& operator=(Framebuffer&& other);
  ~Framebuffer();

  GLuint handle() const { return id_; }
  bool IsValid() const { return id_ != 0; }

  // Binds the framebuffer object as render target.
  bool Bind() const;

  // Attaches the 2D texture |texture| to attachment point |attachment|.
  bool Attach(GLenum attachment, const Texture2D& texture);

 private:
  void Invalidate();

  GLuint id_ = 0;
};

}  // namespace cros

#endif  // CAMERA_GPU_GLES_FRAMEBUFFER_H_
