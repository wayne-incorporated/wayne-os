/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GLES_SHADER_H_
#define CAMERA_GPU_GLES_SHADER_H_

#include <GLES3/gl3.h>

#include <base/files/file_path.h>

#include <optional>
#include <string>

namespace cros {

// A RAII helper class that encapsulates a GL shader object.
class Shader {
 public:
  // Creates a Shader of type |type| from the shader source from file specified
  // by |shader_file_path|.
  static std::optional<Shader> FromFile(GLenum type,
                                        base::FilePath shader_file_path);

  // Creates a Shader of type |type| with shader code from |source_code|.
  Shader(GLenum type, const std::string source_code);
  Shader(const Shader& other) = delete;
  Shader(Shader&& other);
  Shader& operator=(const Shader& other) = delete;
  Shader& operator=(Shader&& other);
  ~Shader();

  GLuint handle() const { return id_; }
  bool IsValid() const { return id_ != 0; }

 private:
  void Invalidate();

  GLuint id_ = 0;
};

}  // namespace cros

#endif  // CAMERA_GPU_GLES_SHADER_H_
