/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/frame_buffer.h"

#include <sys/mman.h>

#include <utility>

#include <hardware/gralloc.h>

#include "cros-camera/common.h"
#include "hal/usb/image_processor.h"

namespace cros {

FrameBuffer::FrameBuffer()
    : data_size_(0),
      buffer_size_(0),
      width_(0),
      height_(0),
      fourcc_(0),
      num_planes_(0) {}

FrameBuffer::~FrameBuffer() {}

uint8_t* FrameBuffer::GetData(size_t plane) const {
  if (plane >= num_planes_ || plane >= data_.size()) {
    LOGF(ERROR) << "Invalid plane " << plane;
    return nullptr;
  }
  return data_[plane];
}

size_t FrameBuffer::GetStride(size_t plane) const {
  if (plane >= num_planes_) {
    LOGF(ERROR) << "Invalid plane " << plane;
    return 0;
  }
  return stride_[plane];
}

void FrameBuffer::SetFourcc(uint32_t fourcc) {
  fourcc_ = fourcc;
}

int FrameBuffer::SetDataSize(size_t data_size) {
  if (data_size > buffer_size_) {
    LOGF(ERROR) << "Buffer overflow: Buffer only has " << buffer_size_
                << ", but data needs " << data_size;
    return -EINVAL;
  }
  data_size_ = data_size;
  return 0;
}

// static
bool SharedFrameBuffer::Reallocate(uint32_t width,
                                   uint32_t height,
                                   uint32_t fourcc,
                                   std::unique_ptr<SharedFrameBuffer>* frame) {
  if (!(*frame)) {
    *frame = std::make_unique<SharedFrameBuffer>(0);
  }
  (*frame)->SetFourcc(fourcc);
  (*frame)->SetWidth(width);
  (*frame)->SetHeight(height);
  size_t data_size = ImageProcessor::GetConvertedSize(**frame);
  if (data_size == 0 || (*frame)->SetDataSize(data_size) != 0) {
    LOGF(ERROR) << "Set data size failed: " << width << "x" << height << " "
                << FormatToString(fourcc) << ", " << data_size;
    return false;
  }
  return true;
}

SharedFrameBuffer::SharedFrameBuffer(int buffer_size) {
  shm_region_ = base::UnsafeSharedMemoryRegion::Create(buffer_size);
  shm_mapping_ = shm_region_.Map();
  buffer_size_ = buffer_size;
  num_planes_ = 1;
  data_.resize(num_planes_, nullptr);
  data_[0] = shm_mapping_.GetMemoryAs<uint8_t>();
  stride_.resize(num_planes_, 0);
}

SharedFrameBuffer::~SharedFrameBuffer() {}

void SharedFrameBuffer::SetWidth(uint32_t width) {
  width_ = width;
  if (fourcc_ && height_) {
    SetStride();
  }
}

void SharedFrameBuffer::SetHeight(uint32_t height) {
  height_ = height;
  if (fourcc_ && width_) {
    SetStride();
  }
}

void SharedFrameBuffer::SetFourcc(uint32_t fourcc) {
  fourcc_ = fourcc;
  if (width_ && height_) {
    SetStride();
  }
}

int SharedFrameBuffer::SetDataSize(size_t data_size) {
  if (data_size > buffer_size_) {
    shm_region_ = base::UnsafeSharedMemoryRegion::Create(data_size);
    shm_mapping_ = shm_region_.Map();
    if (!shm_mapping_.IsValid()) {
      LOGF(ERROR) << "Created Shared Memory Fail";
      return -ENOMEM;
    }
    buffer_size_ = data_size;
  }
  data_size_ = data_size;
  SetData();
  return 0;
}

void SharedFrameBuffer::SetData() {
  switch (fourcc_) {
    case V4L2_PIX_FMT_YUV420:   // YU12
    case V4L2_PIX_FMT_YUV420M:  // YM12, multiple planes YU12
      if (num_planes_ != 3) {
        LOGF(ERROR) << "Stride is not set correctly";
        return;
      }
      data_.resize(num_planes_, 0);
      data_[YPLANE] = shm_mapping_.GetMemoryAs<uint8_t>();
      data_[UPLANE] = data_[YPLANE] + stride_[YPLANE] * height_;
      data_[VPLANE] = data_[UPLANE] + stride_[UPLANE] * height_ / 2;
      break;
    default:
      data_.resize(num_planes_, 0);
      data_[0] = shm_mapping_.GetMemoryAs<uint8_t>();
      break;
  }
}

void SharedFrameBuffer::SetStride() {
  if (!width_ || !height_ || !fourcc_) {
    LOGF(ERROR) << "Invalid width (" << width_ << ") or height (" << height_
                << ") or fourcc (" << FormatToString(fourcc_) << ")";
    return;
  }
  switch (fourcc_) {
    case V4L2_PIX_FMT_YUV420:   // YU12
    case V4L2_PIX_FMT_YUV420M:  // YM12, multiple planes YU12
      num_planes_ = 3;
      stride_.resize(num_planes_, 0);
      stride_[YPLANE] = width_;
      stride_[UPLANE] = stride_[VPLANE] = width_ / 2;
      break;
    default:
      LOGF(ERROR) << "Pixel format " << FormatToString(fourcc_)
                  << " is unsupported.";
      break;
  }
}

V4L2FrameBuffer::V4L2FrameBuffer(base::ScopedFD fd,
                                 int buffer_size,
                                 uint32_t width,
                                 uint32_t height,
                                 uint32_t fourcc)
    : fd_(std::move(fd)), is_mapped_(false) {
  buffer_size_ = buffer_size;
  width_ = width;
  height_ = height;
  fourcc_ = fourcc;

  switch (fourcc_) {
    case V4L2_PIX_FMT_YUV420:
      num_planes_ = 3;
      break;
    default:
      num_planes_ = 1;
      break;
  }
  data_.resize(num_planes_, nullptr);
  stride_.resize(num_planes_, 0);
}

V4L2FrameBuffer::~V4L2FrameBuffer() {
  if (Unmap()) {
    LOGF(ERROR) << "Unmap failed";
  }
}

int V4L2FrameBuffer::Map() {
  base::AutoLock l(lock_);
  if (is_mapped_)
    return 0;

  // TODO(b/141517606): We should tweak the mapping implementation to:
  //   1. Mapped with PROT_READ | PROT_WRITE (Due to: crbug.com/178582)
  //   2. Support non-zero offset
  void* addr = mmap(NULL, buffer_size_, PROT_READ, MAP_SHARED, fd_.get(), 0);
  if (addr == MAP_FAILED) {
    const int ret = ERRNO_OR_RET(-EINVAL);
    PLOGF(ERROR) << "mmap() failed";
    return ret;
  }
  data_[0] = static_cast<uint8_t*>(addr);
  is_mapped_ = true;
  switch (fourcc_) {
    case V4L2_PIX_FMT_Y16:
    case V4L2_PIX_FMT_Z16:
      stride_[0] = width_;
      break;
    case V4L2_PIX_FMT_RGB24:
      stride_[0] = width_ * 3;
      break;
    case V4L2_PIX_FMT_MJPEG:
      stride_[0] = data_size_;
      break;
    case V4L2_PIX_FMT_YUYV:
      stride_[0] = width_ * 2;
      break;
    case V4L2_PIX_FMT_YUV420:
      stride_[0] = width_;
      stride_[1] = (width_ + 1) / 2;
      stride_[2] = (width_ + 1) / 2;
      data_[1] = data_[0] + stride_[0] * height_;
      data_[2] = data_[1] + stride_[1] * (height_ + 1) / 2;
      break;
    default:
      LOGF(WARNING) << "The strides for pixel format "
                    << FormatToString(fourcc_) << " are not given.";
      break;
  }
  return 0;
}

int V4L2FrameBuffer::Unmap() {
  base::AutoLock l(lock_);
  if (!is_mapped_)
    return 0;

  if (munmap(data_[0], buffer_size_)) {
    PLOGF(ERROR) << "mummap() failed";
    return -EINVAL;
  }
  is_mapped_ = false;
  return 0;
}

// static
bool GrallocFrameBuffer::Reallocate(
    uint32_t width,
    uint32_t height,
    uint32_t fourcc,
    std::unique_ptr<GrallocFrameBuffer>* frame) {
  if (!(*frame) || (*frame)->GetWidth() != width ||
      (*frame)->GetHeight() != height || (*frame)->GetFourcc() != fourcc) {
    *frame = std::make_unique<GrallocFrameBuffer>(width, height, fourcc);
  }
  return true;
}

GrallocFrameBuffer::GrallocFrameBuffer(buffer_handle_t buffer,
                                       uint32_t width,
                                       uint32_t height)
    : buffer_(buffer),
      buffer_manager_(CameraBufferManager::GetInstance()),
      is_buffer_owner_(false),
      is_mapped_(false) {
  int ret = buffer_manager_->Register(buffer_);
  if (ret) {
    LOGF(ERROR) << "Failed to register buffer";
    return;
  }
  width_ = width;
  height_ = height;
  fourcc_ = buffer_manager_->GetV4L2PixelFormat(buffer);
  num_planes_ = buffer_manager_->GetNumPlanes(buffer);
  data_.resize(num_planes_, nullptr);
  stride_.resize(num_planes_, 0);
}

GrallocFrameBuffer::GrallocFrameBuffer(uint32_t width,
                                       uint32_t height,
                                       uint32_t fourcc)
    : buffer_(nullptr),
      buffer_manager_(CameraBufferManager::GetInstance()),
      is_buffer_owner_(true),
      is_mapped_(false) {
  if (fourcc != V4L2_PIX_FMT_NV12 && fourcc != V4L2_PIX_FMT_NV12M &&
      fourcc != V4L2_PIX_FMT_YUV420 && fourcc != V4L2_PIX_FMT_YUV420M) {
    LOGF(ERROR) << "Unsupported format: " << FormatToString(fourcc);
    return;
  }
  uint32_t hal_format = HAL_PIXEL_FORMAT_YCbCr_420_888;
  uint32_t hal_usage =
      GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_SW_WRITE_OFTEN;
  if (fourcc == V4L2_PIX_FMT_YUV420 || fourcc == V4L2_PIX_FMT_YUV420M) {
    hal_usage |= GRALLOC_USAGE_FORCE_I420;
  }

  uint32_t stride;
  int ret = buffer_manager_->Allocate(width, height, hal_format, hal_usage,
                                      &buffer_, &stride);
  if (ret) {
    LOGF(ERROR) << "Failed to allocate buffer";
    return;
  }
  width_ = buffer_manager_->GetWidth(buffer_);
  height_ = buffer_manager_->GetHeight(buffer_);
  fourcc_ = buffer_manager_->GetV4L2PixelFormat(buffer_);
  num_planes_ = buffer_manager_->GetNumPlanes(buffer_);
  data_.resize(num_planes_, nullptr);
  stride_.resize(num_planes_, 0);
}

GrallocFrameBuffer::~GrallocFrameBuffer() {
  if (Unmap()) {
    LOGF(ERROR) << "Unmap failed";
  }

  if (is_buffer_owner_) {
    int ret = buffer_manager_->Free(buffer_);
    if (ret) {
      LOGF(ERROR) << "Failed to free buffer";
    }
  } else {
    int ret = buffer_manager_->Deregister(buffer_);
    if (ret) {
      LOGF(ERROR) << "Failed to unregister buffer";
    }
  }
}

int GrallocFrameBuffer::Map() {
  base::AutoLock l(lock_);
  if (is_mapped_)
    return 0;

  buffer_size_ = 0;
  for (size_t i = 0; i < num_planes_; i++) {
    buffer_size_ += buffer_manager_->GetPlaneSize(buffer_, i);
  }

  void* addr;
  int ret;
  switch (fourcc_) {
    case V4L2_PIX_FMT_JPEG:
      ret = buffer_manager_->Lock(buffer_, 0, 0, 0, buffer_size_, 1, &addr);
      if (!ret) {
        data_[0] = static_cast<uint8_t*>(addr);
      }
      break;
    case V4L2_PIX_FMT_RGBX32: {
      ret = buffer_manager_->Lock(buffer_, 0, 0, 0, width_, height_, &addr);
      if (!ret) {
        data_[0] = static_cast<uint8_t*>(addr);
        stride_[0] = width_ * 4;
      }
      break;
    }
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M: {
      struct android_ycbcr ycbcr;
      ret =
          buffer_manager_->LockYCbCr(buffer_, 0, 0, 0, width_, height_, &ycbcr);
      if (!ret) {
        data_[YPLANE] = static_cast<uint8_t*>(ycbcr.y);
        data_[UPLANE] = static_cast<uint8_t*>(ycbcr.cb);
        stride_[YPLANE] = ycbcr.ystride;
        stride_[UPLANE] = ycbcr.cstride;
      }
      break;
    }
    case V4L2_PIX_FMT_YVU420:
    case V4L2_PIX_FMT_YVU420M: {
      struct android_ycbcr ycbcr;
      ret =
          buffer_manager_->LockYCbCr(buffer_, 0, 0, 0, width_, height_, &ycbcr);
      if (!ret) {
        data_[YPLANE] = static_cast<uint8_t*>(ycbcr.y);
        data_[UPLANE] = static_cast<uint8_t*>(ycbcr.cb);
        data_[VPLANE] = static_cast<uint8_t*>(ycbcr.cr);
        stride_[YPLANE] = ycbcr.ystride;
        stride_[UPLANE] = ycbcr.cstride;
        stride_[VPLANE] = ycbcr.cstride;
      }
      break;
    }
    default:
      LOGF(ERROR) << "Format " << FormatToString(fourcc_) << " is unsupported";
      return -EINVAL;
  }

  if (ret) {
    LOGF(ERROR) << "Failed to map buffer";
    return -EINVAL;
  }
  is_mapped_ = true;
  return 0;
}

int GrallocFrameBuffer::Unmap() {
  base::AutoLock l(lock_);
  if (!is_mapped_)
    return 0;

  if (buffer_manager_->Unlock(buffer_)) {
    LOGF(ERROR) << "Failed to unmap buffer";
    return -EINVAL;
  }
  is_mapped_ = false;
  return 0;
}

}  // namespace cros
