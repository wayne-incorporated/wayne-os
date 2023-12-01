/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/fake/frame_buffer/cpu_memory_frame_buffer.h"

#include <sys/mman.h>

#include <utility>

#include <base/memory/ptr_util.h>
#include <base/numerics/checked_math.h>
#include <hardware/gralloc.h>
#include <linux/videodev2.h>
#include <libyuv.h>

#include "cros-camera/common.h"

namespace cros {

CpuMemoryFrameBuffer::ScopedMapping::ScopedMapping(
    base::SafeRef<CpuMemoryFrameBuffer> buffer)
    : buffer_(buffer) {}

CpuMemoryFrameBuffer::ScopedMapping::~ScopedMapping() = default;

uint32_t CpuMemoryFrameBuffer::ScopedMapping::num_planes() const {
  return buffer_->planes_.size();
}

FrameBuffer::ScopedMapping::Plane CpuMemoryFrameBuffer::ScopedMapping::plane(
    int planeIdx) const {
  CHECK(planeIdx >= 0 && planeIdx < buffer_->planes_.size());
  auto plane = buffer_->planes_[planeIdx];
  CHECK(plane.addr != nullptr);
  return plane;
}

CpuMemoryFrameBuffer::CpuMemoryFrameBuffer() = default;

bool CpuMemoryFrameBuffer::Initialize(Size size, uint32_t fourcc) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  size_ = size;
  fourcc_ = fourcc;

  switch (fourcc) {
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M: {
      // TODO(pihsun): Support odd width / height by doing rounding up.
      if (size.width % 2 != 0 || size.height % 2 != 0) {
        LOGF(WARNING) << "Buffer width and height should both be even";
        return false;
      }

      Size plane_sizes[] = {
          size,
          Size(size.width, size.height / 2),
      };
      AllocatePlanes(plane_sizes);
      break;
    }

    case V4L2_PIX_FMT_YUV420:
    case V4L2_PIX_FMT_YUV420M: {
      // TODO(pihsun): Support odd width / height by doing rounding up.
      if (size.width % 2 != 0 || size.height % 2 != 0) {
        LOGF(WARNING) << "Buffer width and height should both be even";
        return false;
      }

      Size plane_sizes[] = {
          size,
          Size(size.width / 2, size.height / 2),
          Size(size.width / 2, size.height / 2),
      };
      AllocatePlanes(plane_sizes);
      break;
    }

    case V4L2_PIX_FMT_JPEG: {
      Size plane_sizes[] = {
          size,
      };
      AllocatePlanes(plane_sizes);
      break;
    }

    default:
      LOGF(WARNING) << "Unsupported format " << FormatToString(fourcc);
      return false;
  }

  return true;
}

CpuMemoryFrameBuffer::~CpuMemoryFrameBuffer() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);
}

std::unique_ptr<FrameBuffer::ScopedMapping> CpuMemoryFrameBuffer::Map() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  return base::WrapUnique(new ScopedMapping(weak_ptr_factory_.GetSafeRef()));
}

void CpuMemoryFrameBuffer::AllocatePlanes(base::span<const Size> sizes) {
  base::CheckedNumeric<size_t> memory_size = 0;
  for (const auto& size : sizes) {
    memory_size += base::CheckMul(size.width, size.height);
  }

  data_ = std::make_unique<uint8_t[]>(memory_size.ValueOrDie());
  planes_.clear();
  planes_.reserve(sizes.size());

  memory_size = 0;
  for (const auto& size : sizes) {
    auto plane_size = base::CheckMul(size.width, size.height);
    planes_.push_back({
        .addr = data_.get() + memory_size.ValueOrDie(),
        .stride = size.width,
        .size = plane_size.ValueOrDie(),
    });
    memory_size += plane_size;
  }
}

}  // namespace cros
