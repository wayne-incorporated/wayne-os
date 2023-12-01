/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_EGL_EGL_FENCE_H_
#define CAMERA_GPU_EGL_EGL_FENCE_H_

#include <base/files/scoped_file.h>
#include <EGL/egl.h>
#include <EGL/eglext.h>

namespace cros {

// A RAII helper class encapsulating a EGLSyncKHR object and provide an
// interface for acquiring native sync FD for inter-process synchronization.
class EglFence {
 public:
  static bool IsSupported();

  // Creates a EGLSyncKHR and insert the fence into the command queue.
  EglFence();

  EglFence(const EglFence& other) = delete;
  EglFence(EglFence&& other);
  EglFence& operator=(const EglFence& other) = delete;
  EglFence& operator=(EglFence&& other);
  ~EglFence();

  bool IsValid() const { return sync_ != EGL_NO_SYNC_KHR; }

  // Gets a native FD that can be passed between processes.  Remote processes
  // can poll / wait on the FD to get the status of the underlying EGLSyncKHR
  // object.
  base::ScopedFD GetNativeFd();

 private:
  void Invalidate();

  EGLDisplay display_ = EGL_NO_DISPLAY;
  EGLSyncKHR sync_ = EGL_NO_SYNC_KHR;
};

}  // namespace cros

#endif  // CAMERA_GPU_EGL_EGL_FENCE_H_
