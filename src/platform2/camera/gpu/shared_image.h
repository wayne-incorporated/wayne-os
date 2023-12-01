/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_SHARED_IMAGE_H_
#define CAMERA_GPU_SHARED_IMAGE_H_

#include <vector>

#include <cutils/native_handle.h>

#include "cros-camera/export.h"
#include "gpu/egl/egl_context.h"
#include "gpu/gles/texture_2d.h"

namespace cros {

// SharedImage holds the different "handles" of a buffer object and is used to
// shared the same buffer across different components (mainly between CPU and
// GPU) without needing to explicitly copying the buffer content.
class CROS_CAMERA_EXPORT SharedImage {
 public:
  // Creates a SharedImage from the given buffer handle |buffer|.
  //
  // If |buffer|'s HAL format is  YUYV (HAL_PIXEL_FORMAT_YCbCr_422_I), this will
  // create two 2D textures for reading Y and UV. Y texture is created with
  // format GR88, whose 1st channel corresponds to Y. UV texture is created with
  // format ABGR8888, whose 2nd and 4th channel correspond to U and V
  // respectively. In this case, |texture_target| and |separate_yuv_textures|
  // are not used.
  //
  // If |separate_yuv_textures| is false, |buffer| will be bound to the
  // texture target |texture_target|.
  // If the format is YUV (semi-)planar and |separate_yuv_textures| is true,
  // then |buffer| will be bound to the Texture2D texture target, since
  // TextureExternalOES doesn't work if we need to write to the underlying
  // DMA-buf.
  static SharedImage CreateFromBuffer(
      buffer_handle_t buffer,
      Texture2D::Target texture_target = Texture2D::Target::kTarget2D,
      bool separate_yuv_textures = false);

  // If fourcc is V4L2_PIX_FMT_YUYV, creates a YUYV SharedImage with format
  // |fourcc|, dimensions |width| x |height|, and DMA-bufs from |planes|. This
  // will create two 2D textures for reading Y and UV. Y texture is created
  // with format GR88, whose 1st channel corresponds to Y. UV texture is
  // created with format ABGR8888, whose 2nd and 4th channel correspond to U
  // and V respectively.
  static SharedImage FromDmaBufFds(const std::vector<DmaBufPlane>& planes,
                                   int width,
                                   int height,
                                   uint32_t fourcc);

  // Creates a SharedImage with the given GL format |gl_format| and dimensions
  // |width| x |height|. The SharedImage image is a pure container of some GPU
  // textures and no DMA-buf buffer will be associated.
  static SharedImage CreateFromGpuTexture(GLenum gl_format,
                                          int width,
                                          int height);

  // Default constructor creates an invalid SharedImage.
  SharedImage() = default;

  SharedImage(const SharedImage& other) = delete;
  SharedImage(SharedImage&&);
  SharedImage& operator=(const SharedImage& other) = delete;
  SharedImage& operator=(SharedImage&& other);
  ~SharedImage();

  const buffer_handle_t& buffer() const { return buffer_; }
  const Texture2D& texture() const;
  const Texture2D& y_texture() const;
  const Texture2D& uv_texture() const;

  void SetDestructionCallback(base::OnceClosure callback);
  bool IsValid();

 private:
  // Creates a SharedImage from the given |buffer|, |egl_images| and |textures|.
  // |buffer| and |egl_images| can be invalid, in which case the SharedImage is
  // simply a container for |textures|.
  //
  // Does not take ownership of |buffer|. The caller must make sure that
  // |buffer| out-lives the SharedImage it's bound to.
  //
  // Takes ownership of |egl_images| and |textures|.
  SharedImage(buffer_handle_t buffer,
              std::vector<EglImage> egl_images,
              std::vector<Texture2D> textures);

  void Invalidate();

  buffer_handle_t buffer_ = nullptr;
  std::vector<EglImage> egl_images_;
  std::vector<Texture2D> textures_;
  base::OnceClosure destruction_callback_;
};

}  // namespace cros

#endif  // CAMERA_GPU_SHARED_IMAGE_H_
