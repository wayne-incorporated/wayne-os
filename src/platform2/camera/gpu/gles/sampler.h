/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_SAMPLER_H_
#define CAMERA_GPU_GLES_SAMPLER_H_

#include <map>

#include <GLES3/gl3.h>     // NOLINT
#include <GLES2/gl2ext.h>  // NOLINT

#include "camera/gpu/egl/egl_image.h"

namespace cros {

// A RAII helper class that encapsulates a GL sampler object.
class Sampler {
 public:
  struct Desc {
    GLenum min_filter = GL_NEAREST_MIPMAP_LINEAR;
    GLenum mag_filter = GL_LINEAR;
    GLfloat min_lod = -1000.0f;
    GLfloat max_lod = 1000.0f;
    GLenum wrap_s = GL_REPEAT;
    GLenum wrap_t = GL_REPEAT;
    GLenum wrap_r = GL_REPEAT;
    GLenum compare_mode = GL_NONE;
    GLenum compare_func = GL_LEQUAL;
  };

  // Default constructor creates an invalid Sampler.
  Sampler() = default;
  explicit Sampler(const Desc& desc);

  Sampler(const Sampler& other) = delete;
  Sampler(Sampler&& other);
  Sampler& operator=(const Sampler& other) = delete;
  Sampler& operator=(Sampler&& other);
  ~Sampler();

  GLuint handle() const { return id_; }
  bool IsValid() const { return id_ != 0; }

  // Binds the Sampler to the texture unit |texture_unit|.
  bool Bind(GLuint texture_unit) const;

  // Unbinds all Samplers associated with texture unit |texture_unit|.
  static void Unbind(GLuint texture_unit);

 private:
  void Invalidate();

  GLuint id_ = 0;
  Desc desc_;
};

// Returns the default Sampler::Desc except with:
// min_filter and mag_filter set to GL_NEAREST.
// wrap_s, wrap_t, and wrap_r set to GL_CLAMP_TO_EDGE.
Sampler::Desc NearestClampToEdge();

// Returns the default Sampler::Desc except with:
// min_filter and mag_filter set to GL_LINEAR.
// wrap_s, wrap_t, and wrap_r set to GL_CLAMP_TO_EDGE.
Sampler::Desc LinearClampToEdge();

}  // namespace cros

#endif  // CAMERA_GPU_GLES_SAMPLER_H_
