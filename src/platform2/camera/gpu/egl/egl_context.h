/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_EGL_EGL_CONTEXT_H_
#define CAMERA_GPU_EGL_EGL_CONTEXT_H_

#include <memory>

#include <base/functional/callback.h>
#include <EGL/eglplatform.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>

namespace cros {

class EglContext;

struct EglContextOptions {
  // The EGL context to share GL objects with.
  const EglContext* share_context = nullptr;

  // The major and minor GLES API version.
  EGLint context_major_version = 3;
  EGLint context_minor_version = 1;
};

// A RAII helper class that encapsulates an EGLContext object.
//
// TODO(jcliang): Allow configuring the context attributes on construction.
class EglContext {
 public:
  // Gets a surfaceless EGL context for offscreen rendering. This requires the
  // EGL_KHR_surfaceless_context extension, which should be supported on all
  // CrOS devices.
  static std::unique_ptr<EglContext> GetSurfacelessContext(
      const EglContextOptions& options = EglContextOptions());

  // Default constructor creates an invalid context.
  EglContext() = default;

  // Creates and initializes an EGLContext. Does not take ownership of
  // |display|.
  explicit EglContext(EGLDisplay display,
                      const EglContextOptions& options = EglContextOptions());

  EglContext(const EglContext& other) = delete;
  EglContext(EglContext&& other);
  EglContext& operator=(const EglContext& other) = delete;
  EglContext& operator=(EglContext&&);
  ~EglContext();

  bool IsValid() const { return context_ != EGL_NO_CONTEXT; }

  // Checks if the EglContext is the current context.
  bool IsCurrent() const;

  // Makes the EglContext the current context.
  bool MakeCurrent();

  // Gets underlying EGLContext object.
  EGLContext Get() const;

 private:
  // Invalidates the EglContext instance.
  void Invalidate();

  EGLDisplay display_ = EGL_NO_DISPLAY;
  EGLContext context_ = EGL_NO_CONTEXT;
};

}  // namespace cros

#endif  // CAMERA_GPU_EGL_EGL_CONTEXT_H_
