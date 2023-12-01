/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/egl/egl_image.h"

#include <utility>
#include <vector>

#include <base/logging.h>
#include <drm_fourcc.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/common.h"
#include "gpu/egl/utils.h"

namespace {

PFNEGLCREATEIMAGEKHRPROC g_eglCreateImageKHR = nullptr;
PFNEGLDESTROYIMAGEKHRPROC g_eglDestroyImageKHR = nullptr;

}  // namespace

namespace cros {

namespace {

bool IsPlanarYuv(uint32_t drm_format) {
  switch (drm_format) {
    case DRM_FORMAT_P010:
    case DRM_FORMAT_NV12:
    case DRM_FORMAT_NV21:
      return true;
    default:
      return false;
  }
}

}  // namespace

// static
bool EglImage::IsSupported() {
  static bool supported = []() -> bool {
    g_eglCreateImageKHR = reinterpret_cast<PFNEGLCREATEIMAGEKHRPROC>(
        eglGetProcAddress("eglCreateImageKHR"));
    g_eglDestroyImageKHR = reinterpret_cast<PFNEGLDESTROYIMAGEKHRPROC>(
        eglGetProcAddress("eglDestroyImageKHR"));
    return (g_eglCreateImageKHR != nullptr) &&
           (g_eglDestroyImageKHR != nullptr);
  }();
  return supported;
}

// static
EglImage EglImage::FromBufferPlane(buffer_handle_t buffer,
                                   int plane,
                                   int width,
                                   int height,
                                   uint32_t drm_format) {
  std::vector<EGLint> attrs = {EGL_WIDTH,
                               static_cast<EGLint>(width),
                               EGL_HEIGHT,
                               static_cast<EGLint>(height),
                               EGL_LINUX_DRM_FOURCC_EXT,
                               static_cast<EGLint>(drm_format)};
  int fd = CameraBufferManager::GetPlaneFd(buffer, plane);
  off_t offset = CameraBufferManager::GetPlaneOffset(buffer, plane);
  size_t stride = CameraBufferManager::GetPlaneStride(buffer, plane);
  attrs.push_back(static_cast<EGLint>(EGL_DMA_BUF_PLANE0_FD_EXT));
  attrs.push_back(fd);
  attrs.push_back(static_cast<EGLint>(EGL_DMA_BUF_PLANE0_OFFSET_EXT));
  attrs.push_back(offset);
  attrs.push_back(static_cast<EGLint>(EGL_DMA_BUF_PLANE0_PITCH_EXT));
  attrs.push_back(stride);
  attrs.push_back(EGL_NONE);

  EglImage image(attrs);
  image.width_ = width;
  image.height_ = height;
  return image;
}

// static
EglImage EglImage::FromBuffer(buffer_handle_t buffer) {
  uint32_t width = CameraBufferManager::GetWidth(buffer);
  uint32_t height = CameraBufferManager::GetHeight(buffer);
  uint32_t drm_format = CameraBufferManager::GetDrmPixelFormat(buffer);
  std::vector<EGLint> attrs = {EGL_WIDTH,
                               static_cast<EGLint>(width),
                               EGL_HEIGHT,
                               static_cast<EGLint>(height),
                               EGL_LINUX_DRM_FOURCC_EXT,
                               static_cast<EGLint>(drm_format)};
  CHECK_LE(CameraBufferManager::GetNumPlanes(buffer), 3);
  for (size_t plane = 0; plane < CameraBufferManager::GetNumPlanes(buffer);
       ++plane) {
    int fd = CameraBufferManager::GetPlaneFd(buffer, plane);
    off_t offset = CameraBufferManager::GetPlaneOffset(buffer, plane);
    size_t stride = CameraBufferManager::GetPlaneStride(buffer, plane);
    attrs.push_back(static_cast<EGLint>(EGL_DMA_BUF_PLANE0_FD_EXT + plane * 3));
    attrs.push_back(fd);
    attrs.push_back(
        static_cast<EGLint>(EGL_DMA_BUF_PLANE0_OFFSET_EXT + plane * 3));
    attrs.push_back(offset);
    attrs.push_back(
        static_cast<EGLint>(EGL_DMA_BUF_PLANE0_PITCH_EXT + plane * 3));
    attrs.push_back(stride);
  }
  if (IsPlanarYuv(drm_format)) {
    // TODO(jcliang): Allow specifying the following attributes.
    attrs.push_back(EGL_YUV_COLOR_SPACE_HINT_EXT);
    attrs.push_back(EGL_ITU_REC601_EXT);
    attrs.push_back(EGL_SAMPLE_RANGE_HINT_EXT);
    attrs.push_back(EGL_YUV_FULL_RANGE_EXT);
    attrs.push_back(EGL_YUV_CHROMA_HORIZONTAL_SITING_HINT_EXT);
    attrs.push_back(EGL_YUV_CHROMA_SITING_0_5_EXT);
    attrs.push_back(EGL_YUV_CHROMA_VERTICAL_SITING_HINT_EXT);
    attrs.push_back(EGL_YUV_CHROMA_SITING_0_5_EXT);
  }
  attrs.push_back(EGL_NONE);

  EglImage image(attrs);
  image.width_ = width;
  image.height_ = height;
  return image;
}

// static
EglImage EglImage::FromDmaBufFds(const std::vector<DmaBufPlane>& planes,
                                 int width,
                                 int height,
                                 uint32_t drm_format) {
  std::vector<EGLint> attrs = {EGL_WIDTH,
                               static_cast<EGLint>(width),
                               EGL_HEIGHT,
                               static_cast<EGLint>(height),
                               EGL_LINUX_DRM_FOURCC_EXT,
                               static_cast<EGLint>(drm_format)};
  for (size_t i = 0; i < planes.size(); ++i) {
    attrs.push_back(static_cast<EGLint>(EGL_DMA_BUF_PLANE0_FD_EXT + i * 3));
    attrs.push_back(planes[i].fd);
    attrs.push_back(static_cast<EGLint>(EGL_DMA_BUF_PLANE0_OFFSET_EXT + i * 3));
    attrs.push_back(planes[i].offset);
    attrs.push_back(static_cast<EGLint>(EGL_DMA_BUF_PLANE0_PITCH_EXT + i * 3));
    attrs.push_back(planes[i].stride);
  }
  attrs.push_back(EGL_NONE);
  EglImage image(attrs);
  image.width_ = width;
  image.height_ = height;
  return image;
}

EglImage::EglImage(EglImage&& other) {
  *this = std::move(other);
}

EglImage& EglImage::operator=(EglImage&& other) {
  if (this != &other) {
    Invalidate();
    image_ = other.image_;
    width_ = other.width_;
    height_ = other.height_;

    other.image_ = EGL_NO_IMAGE_KHR;
    other.width_ = 0;
    other.height_ = 0;
  }
  return *this;
}

EglImage::~EglImage() {
  Invalidate();
}

EglImage::EglImage(const std::vector<EGLint>& attribs) {
  if (!IsSupported()) {
    LOGF(ERROR) << "Creating EGLImageKHR is not supported";
    return;
  }

  image_ = g_eglCreateImageKHR(
      eglGetCurrentDisplay(), EGL_NO_CONTEXT, EGL_LINUX_DMA_BUF_EXT,
      static_cast<EGLClientBuffer>(nullptr), attribs.data());
  EGLint error = eglGetError();
  if (error != EGL_SUCCESS) {
    LOGF(ERROR) << "Failed to create EGL image: " << EglGetErrorString(error);
  }
}

void EglImage::Invalidate() {
  if (IsValid()) {
    g_eglDestroyImageKHR(eglGetCurrentDisplay(), image_);
    image_ = EGL_NO_IMAGE_KHR;
  }
}

}  // namespace cros
