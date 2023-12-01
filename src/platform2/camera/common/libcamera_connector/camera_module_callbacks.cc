/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/common.h"

#include <base/notreached.h>
#include <utility>

#include "common/libcamera_connector/camera_module_callbacks.h"

namespace cros {

CameraModuleCallbacks::CameraModuleCallbacks(
    DeviceStatusCallback device_status_callback)
    : camera_module_callbacks_(this),
      device_status_callback_(std::move(device_status_callback)) {}

mojo::PendingAssociatedRemote<mojom::CameraModuleCallbacks>
CameraModuleCallbacks::GetModuleCallbacks() {
  if (camera_module_callbacks_.is_bound()) {
    camera_module_callbacks_.reset();
  }
  return camera_module_callbacks_.BindNewEndpointAndPassRemote();
}

void CameraModuleCallbacks::CameraDeviceStatusChange(
    int32_t camera_id, mojom::CameraDeviceStatus new_status) {
  LOGF(INFO) << "Camera " << camera_id << " status changed: " << new_status;

  switch (new_status) {
    case mojom::CameraDeviceStatus::CAMERA_DEVICE_STATUS_PRESENT:
      device_status_callback_.Run(camera_id, true);
      break;
    case mojom::CameraDeviceStatus::CAMERA_DEVICE_STATUS_NOT_PRESENT:
      device_status_callback_.Run(camera_id, false);
      break;
    default:
      NOTREACHED() << "Unexpected new device status: " << new_status;
  }
}

void CameraModuleCallbacks::TorchModeStatusChange(
    int32_t camera_id, mojom::TorchModeStatus new_status) {
  // We don't need to do anything for torch mode status change for now.
}

}  // namespace cros
