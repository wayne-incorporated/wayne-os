/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_BUFFER_HANDLE_H_
#define CAMERA_COMMON_CAMERA_BUFFER_HANDLE_H_

#include <cutils/native_handle.h>
#include <drm_fourcc.h>

#include "cros-camera/common.h"

const uint32_t kCameraBufferMagic = 0xD1DAD1DA;
const uint64_t kInvalidBufferId = 0xFFFFFFFFFFFFFFFF;

const size_t kMaxPlanes = 4;

enum BufferState {
  kRegistered = 0,  // The buffer is registered by the framework.
  kReturned = 1,    // The buffer is returned to the framework.
};

typedef struct camera_buffer_handle {
  native_handle_t base;
  // The fds for each plane.
  int fds[kMaxPlanes];
  // Should be kCameraBufferMagic.  This is for basic consistency check.
  uint32_t magic = kCameraBufferMagic;
  // Used to identify the buffer object on the other end of the IPC channel
  // (e.g. the Android container or Chrome browser process.)
  uint64_t buffer_id = kInvalidBufferId;
  // The DRM fourcc code of the buffer.
  uint32_t drm_format = 0;
  // The HAL pixel format of the buffer.
  uint32_t hal_pixel_format = 0;
  // The width of the buffer in pixels.
  uint32_t width = 0;
  // The height of the buffer in pixels.
  uint32_t height = 0;
  // The stride of each plane in bytes.
  uint32_t strides[kMaxPlanes] = {};
  // The offset to the start of each plane in bytes.
  uint32_t offsets[kMaxPlanes] = {};
  // The state of the buffer; must be one of |BufferState|.
  int state = kRegistered;
  // For passing the buffer handle in camera3_stream_buffer_t to the HAL since
  // it requires a buffer_handle_t*.
  buffer_handle_t self = reinterpret_cast<buffer_handle_t>(this);
  // The modifier of the buffer.
  uint64_t modifier = DRM_FORMAT_MOD_INVALID;

  camera_buffer_handle() {
    for (auto& fd : fds) {
      fd = -1;
    }
  }

  ~camera_buffer_handle() {
    for (auto& fd : fds) {
      if (fd == -1) {
        continue;
      }
      // See the comments in base/files/scoped_file.cc in libchrome for why we
      // need to crash here when close fails.
      int ret = IGNORE_EINTR(close(fd));
      if (ret != 0 && errno != EBADF) {
        ret = 0;
      }
      PCHECK(0 == ret);
    }
  }

  static const struct camera_buffer_handle* FromBufferHandle(
      buffer_handle_t handle) {
    auto h = reinterpret_cast<const struct camera_buffer_handle*>(handle);
    if (!h) {
      LOGF(ERROR) << "Invalid buffer handle";
      return nullptr;
    }
    if (h->magic != kCameraBufferMagic) {
      LOGF(ERROR) << "Invalid buffer handle: magic=" << h->magic;
      return nullptr;
    }
    return h;
  }
} camera_buffer_handle_t;

const size_t kCameraBufferHandleNumFds = kMaxPlanes;
const size_t kCameraBufferHandleNumInts =
    (sizeof(struct camera_buffer_handle) - sizeof(native_handle_t) -
     (sizeof(int32_t) * kMaxPlanes)) /
    sizeof(int);

#endif  // CAMERA_COMMON_CAMERA_BUFFER_HANDLE_H_
