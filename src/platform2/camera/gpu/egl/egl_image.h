/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_EGL_EGL_IMAGE_H_
#define CAMERA_GPU_EGL_EGL_IMAGE_H_

#include <vector>

#include <EGL/egl.h>
#include <EGL/eglext.h>

#include <cutils/native_handle.h>

namespace cros {

struct DmaBufPlane {
  const int fd;
  const int stride;
  const int offset;
};

// A RAII helper class that encapsulates an EGLImageKHR object.  We mainly use
// the EGLImageKHR to import DMA-buf and bind the image as textures to avoid
// buffer copy.
class EglImage {
 public:
  static bool IsSupported();

  // Creates an EglImage from the given buffer handle |buffer|.
  static EglImage FromBuffer(buffer_handle_t buffer);

  // Creates an EglImage for the plane |plane| of buffer |buffer|.  The plane
  // will be interpreted as a buffer with dimension |width| x |height| and DRM
  // pixel format |drm_format|.
  static EglImage FromBufferPlane(buffer_handle_t buffer,
                                  int plane,
                                  int width,
                                  int height,
                                  uint32_t drm_format);

  // Creates an EglImage from the given DMA-buf FDs of |planes|.
  static EglImage FromDmaBufFds(const std::vector<DmaBufPlane>& planes,
                                int width,
                                int height,
                                uint32_t drm_format);

  // Default constructor creates an invalid EglImage.
  EglImage() = default;

  EglImage(const EglImage& other) = delete;
  EglImage(EglImage&& other);
  EglImage& operator=(const EglImage& other) = delete;
  EglImage& operator=(EglImage&& other);
  ~EglImage();

  bool IsValid() const { return image_ != EGL_NO_IMAGE_KHR; }
  EGLImageKHR handle() const { return image_; }

  int width() const { return width_; }
  int height() const { return height_; }

 private:
  // EglImage should be created through FromBuffer() or FromBufferPlane().
  explicit EglImage(const std::vector<EGLint>& attribs);
  void Invalidate();

  EGLImageKHR image_ = EGL_NO_IMAGE_KHR;
  int width_ = 0;
  int height_ = 0;
};

}  // namespace cros

#endif  // CAMERA_GPU_EGL_EGL_IMAGE_H_
