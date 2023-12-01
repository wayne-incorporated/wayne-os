/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <errno.h>

#include "common/libcamera_connector/camera_service_connector_impl.h"
#include "cros-camera/camera_service_connector.h"

int cros_cam_init(const cros_cam_init_option_t* option) {
  auto* connector = cros::CameraServiceConnector::GetInstance();
  return connector->Init(option);
}

int cros_cam_exit() {
  auto* connector = cros::CameraServiceConnector::GetInstance();
  return connector->Exit();
}

int cros_cam_get_cam_info(cros_cam_get_cam_info_cb_t callback, void* context) {
  auto* connector = cros::CameraServiceConnector::GetInstance();
  return connector->GetCameraInfo(callback, context);
}

int cros_cam_start_capture(const cros_cam_capture_request_t* request,
                           cros_cam_capture_cb_t callback,
                           void* context) {
  auto* connector = cros::CameraServiceConnector::GetInstance();
  return connector->StartCapture(request, callback, context);
}

int cros_cam_stop_capture(int id) {
  auto* connector = cros::CameraServiceConnector::GetInstance();
  return connector->StopCapture(id);
}
