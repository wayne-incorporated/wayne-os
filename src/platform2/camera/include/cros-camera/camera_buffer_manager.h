/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_BUFFER_MANAGER_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_BUFFER_MANAGER_H_

#include <array>
#include <cstdint>
#include <memory>

#include <cutils/native_handle.h>
#include <sys/types.h>
#include <system/graphics.h>

#include "cros-camera/export.h"

// A V4L2 extension format which represents 32bit RGBX-8-8-8-8 format. This
// corresponds to DRM_FORMAT_XBGR8888 which is used as the underlying format for
// the HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINEND format on all CrOS boards.
#define V4L2_PIX_FMT_RGBX32 v4l2_fourcc('X', 'B', '2', '4')

// A private gralloc usage flag to force allocation of YUV420 buffer.  This
// usage flag is only valid when allocating HAL_PIXEL_FORMAT_YCbCr_420_888
// flexible YUV buffers.
const uint32_t GRALLOC_USAGE_FORCE_I420 = 0x10000000U;

namespace cros {

class GbmDevice;

// RAII class for handling the CPU memory mapping of a camera buffer.  All the
// planes of the camera buffer is mapped when the ScopedMapping is constructed,
// and the address and size of each mapped plane can be accessed through
// ScopedMapping::plane().
class CROS_CAMERA_EXPORT ScopedMapping {
 public:
  struct Plane {
    // The address pointing to the start of the plane.
    uint8_t* addr = nullptr;

    // The byte stride of the plane.
    size_t stride = 0;

    // The size of the mapped memory region of the plane.
    size_t size = 0;
  };

  explicit ScopedMapping(buffer_handle_t buffer);
  ~ScopedMapping();
  ScopedMapping(const ScopedMapping& other) = delete;
  ScopedMapping& operator=(const ScopedMapping& other) = delete;
  ScopedMapping(ScopedMapping&& other);
  ScopedMapping& operator=(ScopedMapping&& other);

  uint32_t width() const;
  uint32_t height() const;
  uint32_t drm_format() const;
  uint32_t v4l2_format() const;
  uint32_t hal_pixel_format() const;
  uint32_t num_planes() const;
  Plane plane(int plane) const;
  bool is_valid() const;

 private:
  static constexpr size_t kMaxPlanes = 4;
  void Invalidate();

  std::array<Plane, kMaxPlanes> planes_;
  buffer_handle_t buf_ = nullptr;
};

// Generic camera buffer manager.  The class is for a camera HAL to map and
// unmap the buffer handles received in camera3_stream_buffer_t.
//
// The class is thread-safe.
//
// Example usage:
//
//  #include <cros-camera/camera_buffer_manager.h>
//  CameraBufferManager* manager = CameraBufferManager::GetInstance();
//  if (!manager) {
//    /* Error handling */
//  }
//
//  /* Register and use a buffer received from IPC */
//
//  manager->Register(buffer_handle);
//  void* addr;
//  manager->Lock(buffer_handle, ..., &addr);
//  /* Access the buffer mapped to |addr| */
//  manager->Unlock(buffer_handle);
//  manager->Deregister(buffer_handle);
//
//  One can also allocate buffers directly from the camera buffer manager:
//
//  /* Allocate locally and use a buffer */
//
//  buffer_handle_t buffer_handle;
//  uint32_t stride;
//  manager->Allocate(..., &buffer_handle, &stride);
//  void* addr;
//  manager->Lock(buffer_handle, ..., &addr);
//  /* Access the buffer mapped to |addr| */
//  manager->Unlock(buffer_handle);
//  manager->Free(buffer_handle);

struct CROS_CAMERA_EXPORT BufferHandleDeleter {
  void operator()(buffer_handle_t* handle);
};

using ScopedBufferHandle =
    std::unique_ptr<buffer_handle_t, BufferHandleDeleter>;

class CROS_CAMERA_EXPORT CameraBufferManager {
 public:
  // Gets the singleton instance.  Returns nullptr if any error occurrs during
  // instance creation.
  static CameraBufferManager* GetInstance();

  virtual ~CameraBufferManager() = default;

  // Allocates a buffer for a frame.
  //
  // Args:
  //    |width|: The width of the frame.
  //    |height|: The height of the frame.
  //    |format|: The HAL pixel format of the frame.
  //    |usage|: The gralloc usage of the buffer.
  //    |out_buffer|: The handle to the allocated buffer.
  //    |out_stride|: The stride of the allocated buffer. |out_stride| is 0 for
  //                  YUV buffers.
  //
  // Returns:
  //    0 on success; corresponding error code on failure.
  virtual int Allocate(size_t width,
                       size_t height,
                       uint32_t format,
                       uint32_t usage,
                       buffer_handle_t* out_buffer,
                       uint32_t* out_stride) = 0;

  // Same as above, but returns a ScopedBufferHandle that deallocates the
  // allocated buffer automatically.
  //
  // Args:
  //    |width|: The width of the frame.
  //    |height|: The height of the frame.
  //    |format|: The HAL pixel format of the frame.
  //    |usage|: The gralloc usage of the buffer.
  //
  // Returns:
  //    A ScopedBufferHandle with valid buffer handle on success, or a
  //    ScopedBufferHandle with nullptr on error.
  static ScopedBufferHandle AllocateScopedBuffer(size_t width,
                                                 size_t height,
                                                 uint32_t format,
                                                 uint32_t usage);

  // Frees |buffer| allocated with CameraBufferManager::Allocate().
  //
  // Args:
  //    |buffer|: The buffer to free.
  //
  // Returns:
  //    0 on success; corresponding error code on failure.
  virtual int Free(buffer_handle_t buffer) = 0;

  // This method is analogous to the register() function in Android gralloc
  // module.  This method needs to be called for buffers that are not allocated
  // with Allocate() before |buffer| can be mapped.
  //
  // Args:
  //    |buffer|: The buffer handle to register.
  //
  // Returns:
  //    0 on success; corresponding error code on failure.
  virtual int Register(buffer_handle_t buffer) = 0;

  // This method is analogous to the unregister() function in Android gralloc
  // module.  After |buffer| is deregistered, calling Lock(), LockYCbCr(), or
  // Unlock() on |buffer| will fail.
  //
  // Args:
  //    |buffer|: The buffer handle to deregister.
  //
  // Returns:
  //    0 on success; corresponding error code on failure.
  virtual int Deregister(buffer_handle_t buffer) = 0;

  // This method is analogous to the lock() function in Android gralloc module.
  // Here the buffer handle is mapped with the given args.
  //
  // This method always maps the entire buffer and |x|, |y|, |width|, |height|
  // do not affect |out_addr|.
  //
  // Args:
  //    |buffer|: The buffer handle to map.
  //    |flags|:  Currently omitted and is reserved for future use.
  //    |x|: Unused and has no effect.
  //    |y|: Unused and has no effect.
  //    |width|: Unused and has no effect.
  //    |height|: Unused and has no effect.
  //    |out_addr|: The mapped address pointing to the start of the buffer.
  //
  // Returns:
  //    0 on success with |out_addr| set with the mapped address;
  //    -EINVAL on invalid buffer handle or invalid buffer format.
  virtual int Lock(buffer_handle_t buffer,
                   uint32_t flags,
                   uint32_t x,
                   uint32_t y,
                   uint32_t width,
                   uint32_t height,
                   void** out_addr) = 0;

  // This method is analogous to the lock_ycbcr() function in Android gralloc
  // module.  Here all the physical planes of the buffer handle are mapped with
  // the given args.
  //
  // This method always maps the entire buffer and |x|, |y|, |width|, |height|
  // do not affect |out_ycbcr|.
  //
  // Args:
  //    |buffer|: The buffer handle to map.
  //    |flags|:  Currently omitted and is reserved for future use.
  //    |x|: Unused and has no effect.
  //    |y|: Unused and has no effect.
  //    |width|: Unused and has no effect.
  //    |height|: Unused and has no effect.
  //    |out_ycbcr|: The mapped addresses, plane strides and chroma offset.
  //        - |out_ycbcr.y| stores the mapped address to the start of the
  //          Y-plane.
  //        - |out_ycbcr.cb| stores the mapped address to the start of the
  //          Cb-plane.
  //        - |out_ycbcr.cr| stores the mapped address to the start of the
  //          Cr-plane.
  //        - |out_ycbcr.ystride| stores the stride of the Y-plane.
  //        - |out_ycbcr.cstride| stores the stride of the chroma planes.
  //        - |out_ycbcr.chroma_step| stores the distance between two adjacent
  //          pixels on the chroma plane. The value is 1 for normal planar
  //          formats, and 2 for semi-planar formats.
  //
  // Returns:
  //    0 on success with |out_ycbcr.y| set with the mapped buffer info;
  //    -EINVAL on invalid buffer handle or invalid buffer format.
  virtual int LockYCbCr(buffer_handle_t buffer,
                        uint32_t flags,
                        uint32_t x,
                        uint32_t y,
                        uint32_t width,
                        uint32_t height,
                        struct android_ycbcr* out_ycbcr) = 0;

  // This method is analogous to the unlock() function in Android gralloc
  // module.  Here the buffer is simply unmapped.
  //
  // Args:
  //    |buffer|: The buffer handle to unmap.
  //
  // Returns:
  //    0 on success; -EINVAL on invalid buffer handle.
  virtual int Unlock(buffer_handle_t buffer) = 0;

  // Resolves the HAL pixel format |hal_format| to the actual DRM format, based
  // on the gralloc usage flags set in |usage|.
  //
  // Args:
  //    |hal_format|: The HAL pixel format to query.
  //    |usage|: The gralloc usage of the buffer.
  //
  // Returns:
  //    The corresponding DRM format; 0 if no DRM format could be resolved to.
  virtual uint32_t ResolveDrmFormat(uint32_t hal_format, uint32_t usage) = 0;

  // Checks if |buffer| is a valid camera buffer handle.
  //
  // Args:
  //    |buffer|: The buffer handle to be verified.
  //
  // Returns:
  //    true if a buffer is valid, or false otherwise.
  static bool IsValidBuffer(buffer_handle_t buffer);

  // Get the width of the buffer handle.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //
  // Returns:
  //    The width; 0 if |buffer| is invalid.
  static uint32_t GetWidth(buffer_handle_t buffer);

  // Get the height of the buffer handle.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //
  // Returns:
  //    The height; 0 if |buffer| is invalid.
  static uint32_t GetHeight(buffer_handle_t buffer);

  // Get the modifier of the buffer handle.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //
  // Returns:
  //    The modifier; DRM_FORMAT_MOD_INVALID if |buffer| is invalid.
  static uint64_t GetModifier(buffer_handle_t buffer);

  // Get the number of physical planes associated with |buffer|.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //
  // Returns:
  //    Number of planes on success; 0 if |buffer| is invalid or unrecognized
  //    pixel format.
  static uint32_t GetNumPlanes(buffer_handle_t buffer);

  // Gets the V4L2 pixel format for the buffer handle.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //
  // Returns:
  //    The V4L2 pixel format; 0 on error.
  static uint32_t GetV4L2PixelFormat(buffer_handle_t buffer);

  // Gets the stride of the specified plane.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //    |plane|: The plane to query.
  //
  // Returns:
  //    The stride of the specified plane; 0 on error.
  static size_t GetPlaneStride(buffer_handle_t buffer, size_t plane);

  // Gets the size of the specified plane.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //    |plane|: The plane to query.
  //
  // Returns:
  //    The size of the specified plane; 0 on error.
  static size_t GetPlaneSize(buffer_handle_t buffer, size_t plane);

  // Gets the offset of the specified plane.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //    |plane|: The plane to query.
  //
  // Returns:
  //    The offset of the specified plane; -1 on error.
  static off_t GetPlaneOffset(buffer_handle_t buffer, size_t plane);

  // Gets the plane fd of the buffer handle.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //
  // Returns:
  //    The plane fd; -1 on error.
  static int GetPlaneFd(buffer_handle_t buffer, size_t plane);

  // Gets the Android HAL pixel format of the buffer handle.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //
  // Returns:
  //    The HAL pixel format as defined in Android's system/graphics.h header;
  //    0 on error.
  static uint32_t GetHalPixelFormat(buffer_handle_t buffer);

  // Gets the DRM pixel format of the buffer handle.
  //
  // Args:
  //    |buffer|: The buffer handle to query.
  //
  // Returns:
  //    The DRM pixel format as defined in drm_fourcc.h header; 0 on error.
  static uint32_t GetDrmPixelFormat(buffer_handle_t buffer);
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_BUFFER_MANAGER_H_
