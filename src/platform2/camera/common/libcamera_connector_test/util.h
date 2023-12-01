/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_LIBCAMERA_CONNECTOR_TEST_UTIL_H_
#define CAMERA_COMMON_LIBCAMERA_CONNECTOR_TEST_UTIL_H_

#include <string>

#include <base/strings/stringprintf.h>

#include "cros-camera/camera_service_connector.h"

namespace cros {
namespace tests {

std::string FacingToString(int facing) {
  switch (facing) {
    case CROS_CAM_FACING_BACK:
      return "back";
    case CROS_CAM_FACING_FRONT:
      return "front";
    case CROS_CAM_FACING_EXTERNAL:
      return "external";
    default:
      return "unknown";
  }
}

std::string FourccToString(uint32_t fourcc) {
  std::string result = "0000";
  for (int i = 0; i < 4; i++) {
    auto c = static_cast<char>(fourcc & 0xFF);
    if (c <= 0x1f || c >= 0x7f) {
      return base::StringPrintf("%#x", fourcc);
    }
    result[i] = c;
    fourcc >>= 8;
  }
  return result;
}

std::string CameraFormatInfoToString(const cros_cam_format_info_t& info) {
  return base::StringPrintf("%s %4ux%4u %3ufps",
                            FourccToString(info.fourcc).c_str(), info.width,
                            info.height, info.fps);
}

bool IsSameFormat(const cros_cam_format_info_t& fmt1,
                  const cros_cam_format_info_t& fmt2) {
  return fmt1.fourcc == fmt2.fourcc && fmt1.width == fmt2.width &&
         fmt1.height == fmt2.height && fmt1.fps == fmt2.fps;
}

}  // namespace tests
}  // namespace cros

#endif  // CAMERA_COMMON_LIBCAMERA_CONNECTOR_TEST_UTIL_H_
