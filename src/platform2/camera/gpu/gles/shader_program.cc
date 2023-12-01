/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/shader_program.h"

#include <algorithm>
#include <utility>

#include "cros-camera/common.h"
#include "gpu/gles/shader.h"

namespace cros {

ShaderProgram::ShaderProgram(const std::vector<const Shader*>& shaders) {
  id_ = glCreateProgram();
  for (const auto* shader : shaders) {
    glAttachShader(id_, shader->handle());
  }
  glLinkProgram(id_);
  for (const auto* shader : shaders) {
    glDetachShader(id_, shader->handle());
  }

  GLint program_log_length;
  glGetProgramiv(id_, GL_INFO_LOG_LENGTH, &program_log_length);
  std::string program_log(std::max(program_log_length - 1, 0), '\0');
  glGetProgramInfoLog(id_, program_log_length, /*length=*/nullptr,
                      program_log.data());
  info_log_ = program_log;

  GLint link_status;
  glGetProgramiv(id_, GL_LINK_STATUS, &link_status);
  if (static_cast<GLboolean>(link_status) == GL_FALSE) {
    Invalidate();
    LOGF(ERROR) << "Shader program failed to link:\n" << info_log_;
  }
}

ShaderProgram::ShaderProgram(ShaderProgram&& other) {
  *this = std::move(other);
}

ShaderProgram& ShaderProgram::operator=(ShaderProgram&& other) {
  if (this != &other) {
    Invalidate();
    id_ = other.id_;
    other.id_ = 0;
  }
  return *this;
}

ShaderProgram::~ShaderProgram() {
  Invalidate();
}

void ShaderProgram::UseProgram() {
  glUseProgram(id_);
}

GLint ShaderProgram::GetUniformLocation(const char* uniform_name) {
  return glGetUniformLocation(id_, uniform_name);
}

void ShaderProgram::Invalidate() {
  if (IsValid()) {
    glDeleteProgram(id_);
    id_ = 0;
  }
}

}  // namespace cros
