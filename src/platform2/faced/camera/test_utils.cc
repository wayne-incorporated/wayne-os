// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/camera/test_utils.h"

#include <vector>

namespace faced::testing {

CameraSet YuvCameraSet() {
  CameraSet yuv_camera_set;
  yuv_camera_set.camera_name = "TestYuvCamera";
  yuv_camera_set.camera_id = 0;
  yuv_camera_set.format_infos = {kYuvHighDefCamera, kYuvStdDefCamera};
  yuv_camera_set.camera_info = {
      .id = yuv_camera_set.camera_id,
      .facing = 0,
      .name = yuv_camera_set.camera_name.c_str(),
      .format_count = static_cast<int>(yuv_camera_set.format_infos.size()),
      .format_info = yuv_camera_set.format_infos.data()};

  // Create fake results
  int width = yuv_camera_set.format_infos[0].width;
  int height = yuv_camera_set.format_infos[0].height;

  yuv_camera_set.data = {std::vector<uint8_t>(width * height, 1),
                         std::vector<uint8_t>(width * (height + 1) / 2, 1)};
  yuv_camera_set.frame = {
      .format = yuv_camera_set.format_infos[0],
      .planes =
          {
              {.stride = width,
               .size = static_cast<int>(yuv_camera_set.data[0].size()),
               .data = yuv_camera_set.data[0].data()},
              {.stride = width,
               .size = static_cast<int>(yuv_camera_set.data[1].size()),
               .data = yuv_camera_set.data[1].data()},
          },
  };
  yuv_camera_set.result = {.status = 0, .frame = &yuv_camera_set.frame};
  return yuv_camera_set;
}

CameraSet MjpgCameraSet() {
  CameraSet mjpg_camera_set;
  mjpg_camera_set.camera_name = "TestMjpgCamera";
  mjpg_camera_set.camera_id = 1;
  mjpg_camera_set.format_infos = {kMjpgCamera};
  mjpg_camera_set.camera_info = {
      .id = mjpg_camera_set.camera_id,
      .facing = 0,
      .name = mjpg_camera_set.camera_name.c_str(),
      .format_count = static_cast<int>(mjpg_camera_set.format_infos.size()),
      .format_info = mjpg_camera_set.format_infos.data()};

  // Create fake results
  int width = mjpg_camera_set.format_infos[0].width;
  int height = mjpg_camera_set.format_infos[0].height;

  mjpg_camera_set.data = {std::vector<uint8_t>(width * height, 1)};
  mjpg_camera_set.frame = {
      .format = mjpg_camera_set.format_infos[0],
      .planes = {{.stride = width,
                  .size = width * height,
                  .data = mjpg_camera_set.data[0].data()}}};
  mjpg_camera_set.result = {.status = 0, .frame = &mjpg_camera_set.frame};
  return mjpg_camera_set;
}

}  // namespace faced::testing
