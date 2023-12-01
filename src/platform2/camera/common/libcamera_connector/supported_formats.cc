/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/libcamera_connector/supported_formats.h"

namespace cros {

namespace {

constexpr std::pair<int, uint32_t> kSupportedFormats[] = {
    {HAL_PIXEL_FORMAT_BLOB, V4L2_PIX_FMT_MJPEG},
    {HAL_PIXEL_FORMAT_YCbCr_420_888, V4L2_PIX_FMT_NV12}};

}

uint32_t GetV4L2PixelFormat(int hal_pixel_format) {
  for (const auto& format_pair : kSupportedFormats) {
    if (format_pair.first == hal_pixel_format) {
      return format_pair.second;
    }
  }
  return 0;
}

int GetHalPixelFormat(uint32_t v4l2_pixel_format) {
  for (const auto& format_pair : kSupportedFormats) {
    if (format_pair.second == v4l2_pixel_format) {
      return format_pair.first;
    }
  }
  return 0;
}

}  // namespace cros
