/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/egl/egl_context.h"

#include <utility>
#include <vector>

#include "cros-camera/common.h"
#include "gpu/egl/utils.h"

namespace cros {

// static
std::unique_ptr<EglContext> EglContext::GetSurfacelessContext(
    const EglContextOptions& options) {
  EGLDisplay egl_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
  if (eglInitialize(egl_display, /*major=*/nullptr, /*minor=*/nullptr) !=
      EGL_TRUE) {
    LOGF(ERROR) << "Failed to create EGL display";
    return std::make_unique<EglContext>();
  }
  // This will leak |egl_display|, but it should be okay.
  return std::make_unique<EglContext>(egl_display, options);
}

EglContext::EglContext(EGLDisplay display, const EglContextOptions& options)
    : display_(display) {
  // Bind API.
  eglBindAPI(EGL_OPENGL_ES_API);

  EGLConfig config = EGL_NO_CONFIG_KHR;

  EGLContext share_context = EGL_NO_CONTEXT;
  if (options.share_context) {
    share_context = options.share_context->Get();
  }

  std::vector<EGLint> context_attribs = {
      EGL_CONTEXT_MAJOR_VERSION,
      options.context_major_version,
      EGL_CONTEXT_MINOR_VERSION,
      options.context_minor_version,
      EGL_NONE,
  };

  context_ =
      eglCreateContext(display_, config, share_context, context_attribs.data());
}

EglContext::EglContext(EglContext&& other) {
  *this = std::move(other);
}

EglContext& EglContext::operator=(EglContext&& other) {
  if (this != &other) {
    Invalidate();
    display_ = other.display_;
    context_ = other.context_;

    other.display_ = EGL_NO_DISPLAY;
    other.context_ = EGL_NO_CONTEXT;
  }
  return *this;
}

EglContext::~EglContext() {
  Invalidate();
}

bool EglContext::IsCurrent() const {
  if (!IsValid()) {
    return false;
  }
  return context_ == eglGetCurrentContext();
}

bool EglContext::MakeCurrent() {
  if (!IsValid()) {
    LOGF(ERROR) << "Cannot make invalid context current";
    return false;
  }
  EGLSurface draw_surface = EGL_NO_SURFACE;
  EGLSurface read_surface = EGL_NO_SURFACE;
  EGLBoolean ok =
      eglMakeCurrent(display_, draw_surface, read_surface, context_);
  EGLint error = eglGetError();
  if (error != EGL_SUCCESS) {
    LOGF(ERROR) << "Failed to make context current: "
                << EglGetErrorString(error);
  }
  return ok == EGL_TRUE;
}

void EglContext::Invalidate() {
  if (IsValid()) {
    if (IsCurrent()) {
      eglReleaseThread();
    }
    if (display_ != EGL_NO_DISPLAY) {
      eglDestroyContext(display_, context_);
      display_ = EGL_NO_DISPLAY;
    }
    context_ = EGL_NO_CONTEXT;
  }
}

EGLContext EglContext::Get() const {
  return context_;
}

}  // namespace cros
