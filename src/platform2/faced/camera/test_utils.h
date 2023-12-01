// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FACED_CAMERA_TEST_UTILS_H_
#define FACED_CAMERA_TEST_UTILS_H_

#include <deque>
#include <string>
#include <vector>

#include <base/task/thread_pool.h>
#include <linux/videodev2.h>

#include "faced/camera/camera_service.h"

namespace faced::testing {

constexpr cros_cam_format_info_t kYuvHighDefCamera = {
    .fourcc = V4L2_PIX_FMT_NV12, .width = 1920, .height = 1080, .fps = 30};
constexpr cros_cam_format_info_t kYuvStdDefCamera = {
    .fourcc = V4L2_PIX_FMT_NV12, .width = 1280, .height = 720, .fps = 30};
constexpr cros_cam_format_info_t kMjpgCamera = {
    .fourcc = V4L2_PIX_FMT_MJPEG, .width = 1280, .height = 720, .fps = 25};

struct CameraSet {
  std::string camera_name;
  int camera_id;
  std::vector<cros_cam_format_info_t> format_infos;
  cros_cam_info_t camera_info;

  // Fake results
  std::vector<std::vector<uint8_t>> data;
  cros_cam_frame_t frame;
  cros_cam_capture_result_t_ result;
};

CameraSet YuvCameraSet();
CameraSet MjpgCameraSet();

}  // namespace faced::testing

#endif  // FACED_CAMERA_TEST_UTILS_H_
