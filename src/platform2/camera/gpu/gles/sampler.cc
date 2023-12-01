/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/sampler.h"

#include <utility>

#include "cros-camera/common.h"
#include "gpu/gles/utils.h"

namespace cros {

Sampler::Sampler(const Desc& desc) {
  glGenSamplers(1, &id_);
  if (id_ == 0) {
    LOGF(ERROR) << "Failed to generate sampler object";
    return;
  }
  desc_ = desc;

  glSamplerParameteri(id_, GL_TEXTURE_MIN_FILTER, desc_.min_filter);
  glSamplerParameteri(id_, GL_TEXTURE_MAG_FILTER, desc_.mag_filter);
  glSamplerParameterf(id_, GL_TEXTURE_MIN_LOD, desc_.min_lod);
  glSamplerParameterf(id_, GL_TEXTURE_MAX_LOD, desc_.max_lod);
  glSamplerParameteri(id_, GL_TEXTURE_WRAP_S, desc_.wrap_s);
  glSamplerParameteri(id_, GL_TEXTURE_WRAP_T, desc_.wrap_t);
  glSamplerParameteri(id_, GL_TEXTURE_WRAP_R, desc_.wrap_r);
  glSamplerParameteri(id_, GL_TEXTURE_COMPARE_MODE, desc_.compare_mode);
  glSamplerParameteri(id_, GL_TEXTURE_COMPARE_FUNC, desc_.compare_func);
}

Sampler::Sampler(Sampler&& other) {
  *this = std::move(other);
}

Sampler& Sampler::operator=(Sampler&& other) {
  if (this != &other) {
    Invalidate();
    id_ = other.id_;
    desc_ = other.desc_;
    other.id_ = 0;
  }
  return *this;
}

Sampler::~Sampler() {
  Invalidate();
}

bool Sampler::Bind(GLuint texture_unit) const {
  if (!IsValid()) {
    LOGF(ERROR) << "Cannot bind invalid sampler";
    return false;
  }
  glBindSampler(texture_unit, id_);
  GLenum result = glGetError();
  if (result != GL_NO_ERROR) {
    LOGF(ERROR) << "Failed to bind sampler to texture unit " << texture_unit
                << ": " << GlGetErrorString(result);
    return false;
  }
  return true;
}

// static
void Sampler::Unbind(GLuint texture_unit) {
  glBindSampler(texture_unit, 0);
}

void Sampler::Invalidate() {
  if (IsValid()) {
    glDeleteSamplers(1, &id_);
    id_ = 0;
  }
}

Sampler::Desc NearestClampToEdge() {
  Sampler::Desc desc;
  desc.min_filter = GL_NEAREST;
  desc.mag_filter = GL_NEAREST;
  desc.wrap_s = GL_CLAMP_TO_EDGE;
  desc.wrap_t = GL_CLAMP_TO_EDGE;
  desc.wrap_r = GL_CLAMP_TO_EDGE;
  return desc;
}

Sampler::Desc LinearClampToEdge() {
  Sampler::Desc desc;
  desc.min_filter = GL_LINEAR;
  desc.mag_filter = GL_LINEAR;
  desc.wrap_s = GL_CLAMP_TO_EDGE;
  desc.wrap_t = GL_CLAMP_TO_EDGE;
  desc.wrap_r = GL_CLAMP_TO_EDGE;
  return desc;
}

}  // namespace cros
