/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/get.h"

namespace cros {

template <>
GLboolean Get(GLenum target) {
  GLboolean result;
  glGetBooleanv(target, &result);
  return result;
}

template <>
GLfloat Get(GLenum target) {
  GLfloat result;
  glGetFloatv(target, &result);
  return result;
}

template <>
GLint Get(GLenum target) {
  GLint result;
  glGetIntegerv(target, &result);
  return result;
}

template <>
GLuint Get(GLenum target) {
  return static_cast<GLuint>(Get<GLint>(target));
}

}  // namespace cros
