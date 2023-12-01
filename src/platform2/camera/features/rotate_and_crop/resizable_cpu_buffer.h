/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_ROTATE_AND_CROP_RESIZABLE_CPU_BUFFER_H_
#define CAMERA_FEATURES_ROTATE_AND_CROP_RESIZABLE_CPU_BUFFER_H_

#include <cstdint>
#include <vector>

namespace cros {

// Wrapper over std::vector that stores an image. The buffer is only
// re-allocated when the buffer size of specified format exceeds current
// capacity.
class ResizableCpuBuffer {
 public:
  // Address and layout information of an image buffer plane.
  struct Plane {
    uint8_t* addr = nullptr;
    uint32_t stride = 0;
    uint32_t size = 0;
  };

  // Changes the pixel format with |drm_format| defined in drm_fourcc.h.
  bool SetFormat(uint32_t width, uint32_t height, uint32_t drm_format);

  // Frees the underlying buffer.
  void Reset();

  // Returns the |index|-th buffer plane.
  const Plane& plane(size_t index) const;

 private:
  std::vector<uint8_t> buffer_;
  std::vector<Plane> planes_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_ROTATE_AND_CROP_RESIZABLE_CPU_BUFFER_H_
