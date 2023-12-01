/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_LIBCAMERA_CONNECTOR_SUPPORTED_FORMATS_H_
#define CAMERA_COMMON_LIBCAMERA_CONNECTOR_SUPPORTED_FORMATS_H_

#include <utility>
#include <vector>

#include <hardware/gralloc.h>
#include <linux/videodev2.h>

namespace cros {

// Gets the corresponding V4L2 pixel format with the given HAL pixel format.
// Returns 0 if no format is found.
uint32_t GetV4L2PixelFormat(int hal_pixel_format);

// Gets the corresponding HAL pixel format with the given V4L2 pixel format.
// Returns 0 if no format is found.
int GetHalPixelFormat(uint32_t v4l2_pixel_format);

}  // namespace cros

#endif  // CAMERA_COMMON_LIBCAMERA_CONNECTOR_SUPPORTED_FORMATS_H_
