/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_FRAME_BUFFER_H_
#define CAMERA_HAL_USB_FRAME_BUFFER_H_

#include <stdint.h>

#include <memory>
#include <string>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/memory/unsafe_shared_memory_region.h>
#include <base/synchronization/lock.h>
#include <camera/camera_metadata.h>

#include "cros-camera/camera_buffer_manager.h"

namespace cros {

class FrameBuffer {
 public:
  enum {
    YPLANE = 0,
    UPLANE = 1,
    VPLANE = 2,
  };

  FrameBuffer();
  virtual ~FrameBuffer();

  // If mapped successfully, the address will be assigned to |data_| and return
  // 0. Otherwise, returns -EINVAL.
  virtual int Map() = 0;

  // Unmaps the mapped address. Returns 0 for success.
  virtual int Unmap() = 0;

  uint8_t* GetData(size_t plane) const;
  uint8_t* GetData() const { return data_[0]; }
  size_t GetDataSize() const { return data_size_; }
  size_t GetBufferSize() const { return buffer_size_; }
  uint32_t GetWidth() const { return width_; }
  uint32_t GetHeight() const { return height_; }
  uint32_t GetFourcc() const { return fourcc_; }
  size_t GetStride(size_t plane) const;
  size_t GetStride() const { return stride_[0]; }
  size_t GetNumPlanes() const { return num_planes_; }

  virtual void SetFourcc(uint32_t fourcc);
  virtual int SetDataSize(size_t data_size);
  virtual int GetFd() const { return -1; }

  virtual buffer_handle_t GetBufferHandle() const { return nullptr; }

 protected:
  std::vector<uint8_t*> data_;
  std::vector<size_t> stride_;

  // The number of bytes used in the buffer.
  size_t data_size_;

  // The number of bytes allocated in the buffer.
  size_t buffer_size_;

  // Frame resolution.
  uint32_t width_;
  uint32_t height_;

  // This is V4L2_PIX_FMT_* in linux/videodev2.h.
  uint32_t fourcc_;

  // The number of planes.
  uint32_t num_planes_;
};

// SharedFrameBuffer is used for the buffer from base::SharedMemory.
class SharedFrameBuffer : public FrameBuffer {
 public:
  static bool Reallocate(uint32_t width,
                         uint32_t height,
                         uint32_t fourcc,
                         std::unique_ptr<SharedFrameBuffer>* frame);

  explicit SharedFrameBuffer(int buffer_size);
  ~SharedFrameBuffer() override;

  // No-op for the two functions.
  int Map() override { return 0; }
  int Unmap() override { return 0; }

  void SetWidth(uint32_t width);
  void SetHeight(uint32_t height);
  void SetFourcc(uint32_t fourcc) override;
  int SetDataSize(size_t data_size) override;
  int GetFd() const override { return shm_region_.GetPlatformHandle().fd; }

 private:
  void SetData();
  void SetStride();
  // base::UnsafeSharedMemoryRegion, instead of the Writable alternative, is
  // used to allow getting (and duplicating in
  // JpegDecodeAcceleratorImpl::IPCBridge::Decode) the fd.
  base::UnsafeSharedMemoryRegion shm_region_;
  base::WritableSharedMemoryMapping shm_mapping_;
};

// V4L2FrameBuffer is used for the buffer from V4L2CameraDevice. Maps the fd
// in constructor. Unmaps and closes the fd in destructor.
class V4L2FrameBuffer : public FrameBuffer {
 public:
  V4L2FrameBuffer(base::ScopedFD fd,
                  int buffer_size,
                  uint32_t width,
                  uint32_t height,
                  uint32_t fourcc);
  // Unmaps |data_| and closes |fd_|.
  ~V4L2FrameBuffer();

  int Map() override;
  int Unmap() override;
  int GetFd() const override { return fd_.get(); }

 private:
  // File descriptor of V4L2 frame buffer.
  base::ScopedFD fd_;

  bool is_mapped_;

  // Lock to guard |is_mapped_|.
  base::Lock lock_;
};

// GrallocFrameBuffer uses CameraBufferManager to manage the buffer.
class GrallocFrameBuffer : public FrameBuffer {
 public:
  static bool Reallocate(uint32_t width,
                         uint32_t height,
                         uint32_t fourcc,
                         std::unique_ptr<GrallocFrameBuffer>* frame);

  // Wraps external buffer from upper framework. Fill |width_| and |height_|
  // according to the parameters.
  GrallocFrameBuffer(buffer_handle_t buffer, uint32_t width, uint32_t height);
  // Allocate the buffer internally.
  GrallocFrameBuffer(uint32_t width, uint32_t height, uint32_t fourcc);
  ~GrallocFrameBuffer();

  // Fill |buffer_size_| and |data_|.
  int Map() override;
  int Unmap() override;

  buffer_handle_t GetBufferHandle() const override { return buffer_; }

 private:
  // The currently used buffer for |buffer_mapper_| operations.
  buffer_handle_t buffer_;

  // Used to import gralloc buffer.
  CameraBufferManager* buffer_manager_;

  // Whether the |buffer_| is allocated by this class.
  bool is_buffer_owner_;

  bool is_mapped_;

  // Lock to guard |is_mapped_|.
  base::Lock lock_;
};

}  // namespace cros

#endif  // CAMERA_HAL_USB_FRAME_BUFFER_H_
