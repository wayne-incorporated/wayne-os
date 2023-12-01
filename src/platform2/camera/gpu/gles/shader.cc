/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/shader.h"

#include <algorithm>
#include <optional>
#include <utility>

#include <base/files/file_util.h>

#include "cros-camera/common.h"

namespace cros {

// static
std::optional<Shader> Shader::FromFile(GLenum type,
                                       base::FilePath shader_file_path) {
  if (!base::PathIsReadable(shader_file_path)) {
    LOGF(ERROR) << "Invalid shader file: " << shader_file_path;
    return std::nullopt;
  }

  std::string source_code;
  bool ok = base::ReadFileToString(shader_file_path, &source_code);
  if (!ok) {
    LOGF(ERROR) << "Failed to load shader source code from file: "
                << shader_file_path;
    return std::nullopt;
  }

  Shader shader(type, std::move(source_code));
  if (!shader.IsValid()) {
    return std::nullopt;
  }

  return std::optional<Shader>(std::move(shader));
}

Shader::Shader(GLenum type, const std::string source_code) {
  id_ = glCreateShader(type);
  if (id_ == 0) {
    LOGF(ERROR) << "Failed to generate shader";
    return;
  }

  VLOGF(1) << "Compiling shader:\n" << source_code.data();
  const char* str = source_code.data();
  const GLint length = source_code.size();
  glShaderSource(id_, 1, &str, &length);
  glCompileShader(id_);

  GLint shader_log_length;
  glGetShaderiv(id_, GL_INFO_LOG_LENGTH, &shader_log_length);
  std::string shader_log(std::max(shader_log_length - 1, 0), '\0');
  glGetShaderInfoLog(id_, shader_log_length, /*length=*/nullptr,
                     shader_log.data());

  GLint compile_status;
  glGetShaderiv(id_, GL_COMPILE_STATUS, &compile_status);
  if (static_cast<GLboolean>(compile_status) == GL_FALSE) {
    glDeleteShader(id_);
    id_ = 0;
    LOGF(ERROR) << "Shader failed to compile:\n" << shader_log;
    return;
  }
}

Shader::Shader(Shader&& other) {
  *this = std::move(other);
}

Shader& Shader::operator=(Shader&& other) {
  if (this != &other) {
    Invalidate();
    id_ = other.id_;
    other.id_ = 0;
  }
  return *this;
}

Shader::~Shader() {
  Invalidate();
}

void Shader::Invalidate() {
  if (IsValid()) {
    glDeleteShader(id_);
    id_ = 0;
  }
}

}  // namespace cros
