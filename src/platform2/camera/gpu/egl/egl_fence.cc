/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/egl/egl_fence.h"

#include <utility>

#include <GLES3/gl3.h>

#include "cros-camera/common.h"
#include "gpu/tracing.h"

namespace {

PFNEGLCREATESYNCKHRPROC g_eglCreateSyncKHR = nullptr;
PFNEGLDESTROYSYNCKHRPROC g_eglDestroySyncKHR = nullptr;
PFNEGLDUPNATIVEFENCEFDANDROIDPROC g_eglDupNativeFenceFDANDROID = nullptr;

}  // namespace

namespace cros {

// static
bool EglFence::IsSupported() {
  static bool supported = []() -> bool {
    g_eglCreateSyncKHR = reinterpret_cast<PFNEGLCREATESYNCKHRPROC>(
        eglGetProcAddress("eglCreateSyncKHR"));
    g_eglDestroySyncKHR = reinterpret_cast<PFNEGLDESTROYSYNCKHRPROC>(
        eglGetProcAddress("eglDestroySyncKHR"));
    g_eglDupNativeFenceFDANDROID =
        reinterpret_cast<PFNEGLDUPNATIVEFENCEFDANDROIDPROC>(
            eglGetProcAddress("eglDupNativeFenceFDANDROID"));
    return (g_eglCreateSyncKHR != nullptr) &&
           (g_eglDestroySyncKHR != nullptr) &&
           (g_eglDupNativeFenceFDANDROID != nullptr);
  }();
  return supported;
}

EglFence::EglFence() {
  TRACE_GPU_DEBUG();

  if (!IsSupported()) {
    LOGF(ERROR) << "Creating EGLSyncKHR isn't supported";
    return;
  }

  display_ = eglGetCurrentDisplay();
  if (display_ != EGL_NO_DISPLAY) {
    sync_ =
        g_eglCreateSyncKHR(display_, EGL_SYNC_NATIVE_FENCE_ANDROID, nullptr);
    glFlush();
  }
  if (sync_ == EGL_NO_SYNC_KHR) {
    LOGF(ERROR) << "Failed to create EGL sync";
  }
}

EglFence::EglFence(EglFence&& other) {
  *this = std::move(other);
}

EglFence& EglFence::operator=(EglFence&& other) {
  if (this != &other) {
    Invalidate();
    display_ = other.display_;
    sync_ = other.sync_;
    other.display_ = EGL_NO_DISPLAY;
    other.sync_ = EGL_NO_SYNC_KHR;
  }
  return *this;
}

EglFence::~EglFence() {
  Invalidate();
}

base::ScopedFD EglFence::GetNativeFd() {
  TRACE_GPU_DEBUG();

  if (!IsValid()) {
    return base::ScopedFD();
  }
  const EGLint sync_fd = g_eglDupNativeFenceFDANDROID(display_, sync_);
  if (sync_fd == EGL_NO_NATIVE_FENCE_FD_ANDROID) {
    LOGF(ERROR) << "Failed to get native sync FD";
  }
  return base::ScopedFD(sync_fd);
}

void EglFence::Invalidate() {
  TRACE_GPU_DEBUG();

  if (IsValid()) {
    g_eglDestroySyncKHR(display_, sync_);
    display_ = EGL_NO_DISPLAY;
    sync_ = EGL_NO_SYNC_KHR;
  }
}

}  // namespace cros
