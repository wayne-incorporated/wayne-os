/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/texture_2d.h"

#include <utility>

#include <GLES3/gl31.h>

#include "cros-camera/common.h"
#include "gpu/gles/utils.h"

PFNGLEGLIMAGETARGETTEXTURE2DOESPROC g_glEGLImageTargetTexture2DOES = nullptr;

namespace cros {

// static
bool Texture2D::IsExternalTextureSupported() {
  static bool supported = []() -> bool {
    g_glEGLImageTargetTexture2DOES =
        reinterpret_cast<PFNGLEGLIMAGETARGETTEXTURE2DOESPROC>(
            eglGetProcAddress("glEGLImageTargetTexture2DOES"));
    return g_glEGLImageTargetTexture2DOES != nullptr;
  }();
  return supported;
}

Texture2D::Texture2D(Target target, const EglImage& egl_image)
    : width_(egl_image.width()), height_(egl_image.height()) {
  target_ = [target]() {
    switch (target) {
      case Texture2D::Target::kTarget2D:
        return GL_TEXTURE_2D;
      case Texture2D::Target::kTargetExternal:
        return GL_TEXTURE_EXTERNAL_OES;
    }
  }();

  if (!IsExternalTextureSupported()) {
    LOGF(ERROR) << "Creating external texture isn't supported";
    return;
  }

  glGenTextures(1, &id_);
  if (id_ == 0) {
    LOGF(ERROR) << "Failed to generate texture";
    return;
  }

  Bind();
  g_glEGLImageTargetTexture2DOES(target_, egl_image.handle());
  GLenum result = glGetError();
  if (result != GL_NO_ERROR) {
    LOGF(ERROR) << "Failed to bind external EGL image: "
                << GlGetErrorString(result);
    Invalidate();
    return;
  }
  if (target_ == GL_TEXTURE_2D) {
    glGetTexLevelParameteriv(target_, 0, GL_TEXTURE_INTERNAL_FORMAT,
                             reinterpret_cast<GLint*>(&internal_format_));
  }
  Unbind();
}

Texture2D::Texture2D(GLenum internal_format,
                     int width,
                     int height,
                     int mipmap_levels)
    : target_(GL_TEXTURE_2D),
      internal_format_(internal_format),
      width_(width),
      height_(height) {
  glGenTextures(1, &id_);
  GLenum result = glGetError();
  if (result != GL_NO_ERROR) {
    LOGF(ERROR) << "Failed to generate texture: " << GlGetErrorString(result);
    return;
  }

  glBindTexture(target_, id_);
  glTexStorage2D(target_, mipmap_levels, internal_format, width_, height_);
  result = glGetError();
  if (result != GL_NO_ERROR) {
    LOGF(ERROR) << "Failed to configure texture storage: "
                << GlGetErrorString(result);
    Invalidate();
    return;
  }
  glBindTexture(target_, 0);
}

Texture2D::Texture2D(Texture2D&& other) {
  *this = std::move(other);
}

Texture2D::Texture2D(GLuint texture,
                     GLenum internal_format,
                     int width,
                     int height,
                     int mipmap_levels)
    : target_(GL_TEXTURE_2D),
      id_(texture),
      internal_format_(internal_format),
      width_(width),
      height_(height) {}

Texture2D& Texture2D::operator=(Texture2D&& other) {
  if (this != &other) {
    Invalidate();
    target_ = other.target_;
    id_ = other.id_;
    internal_format_ = other.internal_format_;
    width_ = other.width_;
    height_ = other.height_;

    other.target_ = 0;
    other.id_ = 0;
    other.internal_format_ = GL_NONE;
    other.width_ = 0;
    other.height_ = 0;
  }
  return *this;
}

Texture2D::~Texture2D() {
  Invalidate();
}

void Texture2D::Bind() const {
  glBindTexture(target_, id_);
}

void Texture2D::Unbind() const {
  glBindTexture(target_, 0);
}

void Texture2D::Invalidate() {
  if (IsValid()) {
    glDeleteTextures(1, &id_);
    id_ = 0;
  }
}

}  // namespace cros
