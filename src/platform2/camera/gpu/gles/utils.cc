/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gles/utils.h"

#include <GLES3/gl3.h>
#include <GLES3/gl32.h>

#include <base/strings/stringprintf.h>

#include "cros-camera/common.h"

namespace cros {

#define CASE_STR(value) \
  case value:           \
    return std::string(#value);
std::string GlGetErrorString(GLint error) {
  switch (error) {
    CASE_STR(GL_NO_ERROR)
    CASE_STR(GL_INVALID_ENUM)
    CASE_STR(GL_INVALID_VALUE)
    CASE_STR(GL_INVALID_OPERATION)
    CASE_STR(GL_INVALID_FRAMEBUFFER_OPERATION)
    CASE_STR(GL_OUT_OF_MEMORY)
    CASE_STR(GL_STACK_UNDERFLOW)
    CASE_STR(GL_STACK_OVERFLOW)
    default:
      return base::StringPrintf("Unknown GL ERROR: %d", error);
  }
}
#undef CASE_STR

void GlDumpInfo() {
  LOGF(INFO) << "OpenGL ES initialized.";
  LOGF(INFO) << "Version: " << glGetString(GL_VERSION);
  LOGF(INFO) << "Vendor: " << glGetString(GL_VENDOR);
  LOGF(INFO) << "Renderer: " << glGetString(GL_RENDERER);
  LOGF(INFO) << "GLSL Version: " << glGetString(GL_SHADING_LANGUAGE_VERSION);
  LOGF(INFO) << "Extensions: " << glGetString(GL_EXTENSIONS);
}

}  // namespace cros
