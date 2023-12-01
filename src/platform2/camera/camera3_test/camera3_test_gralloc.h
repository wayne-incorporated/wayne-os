// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_TEST_GRALLOC_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_TEST_GRALLOC_H_

#include <memory>
#include <unordered_map>

#include <base/synchronization/lock.h>
#include <cros-camera/camera_buffer_manager.h>
#include <gbm.h>
#include <xf86drm.h>

#include "common/camera_buffer_handle.h"

namespace camera3_test {

class Camera3TestGralloc {
 public:
  // Get Gralloc single instance
  static Camera3TestGralloc* GetInstance();

  // Allocate buffer by given parameters
  cros::ScopedBufferHandle Allocate(int width,
                                    int height,
                                    int format,
                                    int usage);

  // This method is analogous to the lock() function in Android gralloc module.
  // Here the buffer handle is mapped with the given args.
  //
  // Args:
  //    |buffer|: The buffer handle to map.
  //    |flags|:  Currently omitted and is reserved for future use.
  //    |x|: The base x coordinate in pixels.
  //    |y|: The base y coordinate in pixels.
  //    |width|: The width in pixels of the area to map.
  //    |height|: The height in pixels of the area to map.
  //    |out_addr|: The mapped address.
  //
  // Returns:
  //    0 on success with |out_addr| set with the mapped address;
  //    -EINVAL on invalid buffer handle or invalid buffer format.
  int Lock(buffer_handle_t buffer,
           uint32_t flags,
           uint32_t x,
           uint32_t y,
           uint32_t width,
           uint32_t height,
           void** out_addr);

  // This method is analogous to the lock_ycbcr() function in Android gralloc
  // module.  Here all the physical planes of the buffer handle are mapped with
  // the given args.
  //
  // Args:
  //    |buffer|: The buffer handle to map.
  //    |flags|:  Currently omitted and is reserved for future use.
  //    |x|: The base x coordinate in pixels.
  //    |y|: The base y coordinate in pixels.
  //    |width|: The width in pixels of the area to map.
  //    |height|: The height in pixels of the area to map.
  //    |out_ycbcr|: The mapped addresses, plane strides and chroma offset.
  //        - |out_ycbcr.y| stores the mapped address of the Y-plane.
  //        - |out_ycbcr.cb| stores the mapped address of the Cb-plane.
  //        - |out_ycbcr.cr| stores the mapped address of the Cr-plane.
  //        - |out_ycbcr.ystride| stores the stride of the Y-plane.
  //        - |out_ycbcr.cstride| stores the stride of the chroma planes.
  //        - |out_ycbcr.chroma_step| stores the distance between two adjacent
  //          pixels on the chroma plane. The value is 1 for normal planar
  //          formats, and 2 for semi-planar formats.
  //
  // Returns:
  //    0 on success with |out_ycbcr.y| set with the mapped buffer info;
  //    -EINVAL on invalid buffer handle or invalid buffer format.
  int LockYCbCr(buffer_handle_t buffer,
                uint32_t flags,
                uint32_t x,
                uint32_t y,
                uint32_t width,
                uint32_t height,
                struct android_ycbcr* out_ycbcr);

  // This method is analogous to the unlock() function in Android gralloc
  // module.  Here the buffer is simply unmapped.
  //
  // Args:
  //    |buffer|: The buffer handle to unmap.
  //
  // Returns:
  //    0 on success; -EINVAL on invalid buffer handle.
  int Unlock(buffer_handle_t buffer);

  // Get buffer format
  // Returns:
  //    HAL_PIXEL_FORMAT_* on success; -EINVAL on invalid buffer handle.
  static int GetFormat(buffer_handle_t buffer);

  // Get V4L2 pixel format
  // Returns:
  //    V4L2 pixel format on success; 0 on failure.
  static uint32_t GetV4L2PixelFormat(buffer_handle_t buffer);

  // Get the width of the buffer handle.
  // Returns:
  //    The width; 0 if |buffer| is invalid.
  static uint32_t GetWidth(buffer_handle_t buffer);

  // Get the height of the buffer handle.
  // Returns:
  //    The height; 0 if |buffer| is invalid.
  static uint32_t GetHeight(buffer_handle_t buffer);

 private:
  Camera3TestGralloc();

  bool Initialize();

  // Lock to protect the singleton creation
  static base::Lock lock_;

  cros::CameraBufferManager* buffer_manager_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_TEST_GRALLOC_H_
