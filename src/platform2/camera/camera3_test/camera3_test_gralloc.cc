// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_test_gralloc.h"

#include <drm_fourcc.h>
#include <linux/videodev2.h>

#include <algorithm>

#include <base/files/file_util.h>
#include <cros-camera/camera_buffer_manager.h>

namespace camera3_test {

base::Lock Camera3TestGralloc::lock_;

// static
Camera3TestGralloc* Camera3TestGralloc::GetInstance() {
  static std::unique_ptr<Camera3TestGralloc> gralloc;
  base::AutoLock l(lock_);
  if (!gralloc) {
    gralloc.reset(new Camera3TestGralloc());
    if (!gralloc->Initialize()) {
      gralloc.reset();
    }
  }
  return gralloc.get();
}

Camera3TestGralloc::Camera3TestGralloc()
    : buffer_manager_(cros::CameraBufferManager::GetInstance()) {}

bool Camera3TestGralloc::Initialize() {
  if (!buffer_manager_) {
    LOG(ERROR) << "Failed to get buffer mapper";
    return false;
  }
  return true;
}

cros::ScopedBufferHandle Camera3TestGralloc::Allocate(int32_t width,
                                                      int32_t height,
                                                      int32_t format,
                                                      int32_t usage) {
  return cros::CameraBufferManager::AllocateScopedBuffer(width, height, format,
                                                         usage);
}

int Camera3TestGralloc::Lock(buffer_handle_t buffer,
                             uint32_t flags,
                             uint32_t x,
                             uint32_t y,
                             uint32_t width,
                             uint32_t height,
                             void** out_addr) {
  return buffer_manager_->Lock(buffer, flags, x, y, width, height, out_addr);
}

int Camera3TestGralloc::LockYCbCr(buffer_handle_t buffer,
                                  uint32_t flags,
                                  uint32_t x,
                                  uint32_t y,
                                  uint32_t width,
                                  uint32_t height,
                                  struct android_ycbcr* out_ycbcr) {
  return buffer_manager_->LockYCbCr(buffer, flags, x, y, width, height,
                                    out_ycbcr);
}

int Camera3TestGralloc::Unlock(buffer_handle_t buffer) {
  return buffer_manager_->Unlock(buffer);
}

// static
int Camera3TestGralloc::GetFormat(buffer_handle_t buffer) {
  auto hnd = camera_buffer_handle_t::FromBufferHandle(buffer);
  return (hnd && hnd->buffer_id) ? hnd->hal_pixel_format : -EINVAL;
}

// static
uint32_t Camera3TestGralloc::GetV4L2PixelFormat(buffer_handle_t buffer) {
  return cros::CameraBufferManager::GetInstance()->GetV4L2PixelFormat(buffer);
}

// static
uint32_t Camera3TestGralloc::GetWidth(buffer_handle_t buffer) {
  return cros::CameraBufferManager::GetInstance()->GetWidth(buffer);
}

// static
uint32_t Camera3TestGralloc::GetHeight(buffer_handle_t buffer) {
  return cros::CameraBufferManager::GetInstance()->GetHeight(buffer);
}

}  // namespace camera3_test
