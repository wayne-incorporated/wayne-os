/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_TEXTURE_2D_H_
#define CAMERA_GPU_GLES_TEXTURE_2D_H_

#include <map>

#include <GLES3/gl3.h>
#include <GLES2/gl2ext.h>

#include "camera/gpu/egl/egl_image.h"

namespace cros {

// A RAII helper class that encapsulates a GL 2D texture object.
class Texture2D {
 public:
  enum class Target : GLenum {
    kTarget2D = GL_TEXTURE_2D,
    // For sampling external DMA-buf buffers.
    kTargetExternal = GL_TEXTURE_EXTERNAL_OES,
  };

  static bool IsExternalTextureSupported();

  // Default constructor creates an invalid Texture2D.
  Texture2D() = default;

  // Creates a Texture2D from the EglImage |egl_image|.  The texture will be
  // bound to texture target |target| when Bind() is called.
  Texture2D(Target target, const EglImage& egl_image);

  // Creates a Texture2D backed by GPU memory with internl format
  // |internal_format| and dimensions |width| x |height|.
  Texture2D(GLenum internal_format,
            int width,
            int height,
            int mipmap_levels = 1);

  // Wraps an existing GL texture with internal format |internal_format| and
  // dimensions |width| x |height|.
  Texture2D(GLuint texture,
            GLenum internal_format,
            int width,
            int height,
            int mipmap_levels = 1);

  Texture2D(const Texture2D& other) = delete;
  Texture2D(Texture2D&& other);
  Texture2D& operator=(const Texture2D& other) = delete;
  Texture2D& operator=(Texture2D&& other);
  ~Texture2D();

  GLuint handle() const { return id_; }
  bool IsValid() const { return id_ != 0; }

  // Binds the texture to the target specified in the constructor.
  void Bind() const;
  // Unbinds the texture from the target specified in the constructor.
  void Unbind() const;

  // The GL internal format of the texture.
  GLenum internal_format() const { return internal_format_; }
  // The texel width of the texture.
  int width() const { return width_; }
  // The texel height of the texture.
  int height() const { return height_; }
  // The texture target for this texture object.
  GLenum target() const { return target_; }

  // Release ownership of texture to caller.
  GLuint Release() {
    GLuint ret(id_);
    id_ = 0;
    return ret;
  }

 private:
  void Invalidate();

  GLenum target_ = 0;
  GLuint id_ = 0;
  GLenum internal_format_ = GL_NONE;
  int width_ = 0;
  int height_ = 0;
};

}  // namespace cros

#endif  // CAMERA_GPU_GLES_TEXTURE_2D_H_
