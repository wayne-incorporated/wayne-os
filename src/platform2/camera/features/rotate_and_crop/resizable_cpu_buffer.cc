/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/rotate_and_crop/resizable_cpu_buffer.h"

#include <drm_fourcc.h>

#include <base/bits.h>

#include "cros-camera/common.h"

namespace cros {

bool ResizableCpuBuffer::SetFormat(uint32_t width,
                                   uint32_t height,
                                   uint32_t drm_format) {
  planes_.clear();

  if (width == 0 || height == 0) {
    LOGF(ERROR) << "Invalid width/height";
    return false;
  }

  switch (drm_format) {
    case DRM_FORMAT_YUV420:
      width = base::bits::AlignUp(width, 2u);
      height = base::bits::AlignUp(height, 2u);
      buffer_.resize(width * height * 3 / 2);
      planes_.push_back(Plane{
          .addr = buffer_.data(),
          .stride = width,
          .size = width * height,
      });
      planes_.push_back(Plane{
          .addr = planes_.back().addr + planes_.back().size,
          .stride = width / 2,
          .size = width * height / 4,
      });
      planes_.push_back(Plane{
          .addr = planes_.back().addr + planes_.back().size,
          .stride = width / 2,
          .size = width * height / 4,
      });
      break;

    case DRM_FORMAT_NV12:
      width = base::bits::AlignUp(width, 2u);
      height = base::bits::AlignUp(height, 2u);
      buffer_.resize(width * height * 3 / 2);
      planes_.push_back(Plane{
          .addr = buffer_.data(),
          .stride = width,
          .size = width * height,
      });
      planes_.push_back(Plane{
          .addr = planes_.back().addr + planes_.back().size,
          .stride = width,
          .size = width * height / 2,
      });
      break;

    default:
      LOGF(ERROR) << "Unsupported DRM format: " << drm_format;
      return false;
  }

  return true;
}

void ResizableCpuBuffer::Reset() {
  planes_.clear();
  buffer_ = std::vector<uint8_t>();
}

const ResizableCpuBuffer::Plane& ResizableCpuBuffer::plane(size_t index) const {
  CHECK_LT(index, planes_.size());
  return planes_.at(index);
}

}  // namespace cros
