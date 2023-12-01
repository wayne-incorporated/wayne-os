/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/egl/utils.h"

#include <base/logging.h>

namespace cros {

#define CASE_STR(value) \
  case value:           \
    return #value;
const char* EglGetErrorString(EGLint error) {
  switch (error) {
    CASE_STR(EGL_SUCCESS)
    CASE_STR(EGL_NOT_INITIALIZED)
    CASE_STR(EGL_BAD_ACCESS)
    CASE_STR(EGL_BAD_ALLOC)
    CASE_STR(EGL_BAD_ATTRIBUTE)
    CASE_STR(EGL_BAD_CONTEXT)
    CASE_STR(EGL_BAD_CONFIG)
    CASE_STR(EGL_BAD_CURRENT_SURFACE)
    CASE_STR(EGL_BAD_DISPLAY)
    CASE_STR(EGL_BAD_SURFACE)
    CASE_STR(EGL_BAD_MATCH)
    CASE_STR(EGL_BAD_PARAMETER)
    CASE_STR(EGL_BAD_NATIVE_PIXMAP)
    CASE_STR(EGL_BAD_NATIVE_WINDOW)
    CASE_STR(EGL_CONTEXT_LOST)
    default:
      return "Unknown EGL ERROR";
  }
}
#undef CASE_STR

void EglDumpInfo() {
  const EGLDisplay display = eglGetCurrentDisplay();
  LOG(INFO) << "EGL initialized.";
  LOG(INFO) << "Version: " << eglQueryString(display, EGL_VERSION);
  LOG(INFO) << "Vendor: " << eglQueryString(display, EGL_VENDOR);
  LOG(INFO) << "Client APIs: " << eglQueryString(display, EGL_CLIENT_APIS);
  LOG(INFO) << "Extensions: " << eglQueryString(display, EGL_EXTENSIONS);
}

}  // namespace cros
