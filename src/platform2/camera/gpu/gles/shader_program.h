/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_SHADER_PROGRAM_H_
#define CAMERA_GPU_GLES_SHADER_PROGRAM_H_

#include <GLES3/gl3.h>

#include <string>
#include <vector>

#include <base/containers/span.h>

#include "gpu/gles/shader.h"

namespace cros {

// A RAII helper class that encapsulates a GL shader program object.
class ShaderProgram {
 public:
  // Default constructor creates an invalid ShaderProgram.
  ShaderProgram() = default;

  // Creates a ShaderProgram by linking the shaders in |shaders| together.
  explicit ShaderProgram(const std::vector<const Shader*>& shaders);

  ShaderProgram(const ShaderProgram&) = delete;
  ShaderProgram(ShaderProgram&& other);
  ShaderProgram& operator=(const ShaderProgram&) = delete;
  ShaderProgram& operator=(ShaderProgram&& other);
  ~ShaderProgram();

  // Activates the ShaderProgram in the rendering pipeline.
  void UseProgram();

  // Gets the location of the uniform specified by |uniform_name|.
  GLint GetUniformLocation(const char* uniform_name);

  GLuint handle() { return id_; }
  bool IsValid() { return id_ != 0; }

  std::string info_log() const { return info_log_; }

 private:
  void Invalidate();

  GLuint id_ = 0;
  std::string info_log_;
};

}  // namespace cros

#endif  // CAMERA_GPU_GLES_SHADER_PROGRAM_H_
