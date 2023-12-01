/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal_adapter/camera_hal_test_adapter.h"

#include <optional>
#include <string>

#include "cros-camera/common.h"
#include "cros-camera/future.h"

namespace cros {

CameraHalTestAdapter::CameraHalTestAdapter(
    std::vector<std::pair<camera_module_t*, cros_camera_hal_t*>>
        camera_interfaces,
    CameraMojoChannelManagerToken* token,
    CameraActivityCallback activity_callback,
    bool enable_front,
    bool enable_back,
    bool enable_external)
    : CameraHalAdapter(camera_interfaces, token, activity_callback),
      enable_front_(enable_front),
      enable_back_(enable_back),
      enable_external_(enable_external) {
  LOGF(INFO) << "Filter options: enable_front=" << enable_front_
             << ", enable_back=" << enable_back_
             << ", enable_external=" << enable_external_;
}

int32_t CameraHalTestAdapter::OpenDevice(
    int32_t camera_id,
    mojo::PendingReceiver<mojom::Camera3DeviceOps> device_ops_receiver,
    cros::mojom::CameraClientType camera_client_type) {
  std::optional<int> unremapped_id = GetUnRemappedCameraId(camera_id);
  if (!unremapped_id) {
    return -EINVAL;
  }
  LOGF(INFO) << "From remap camera id " << camera_id << " to "
             << *unremapped_id;
  return CameraHalAdapter::OpenDevice(
      *unremapped_id, std::move(device_ops_receiver), camera_client_type);
}

int32_t CameraHalTestAdapter::GetNumberOfCameras() {
  return enable_camera_ids_.size();
}

int32_t CameraHalTestAdapter::GetCameraInfo(
    int32_t camera_id,
    mojom::CameraInfoPtr* camera_info,
    cros::mojom::CameraClientType camera_client_type) {
  std::optional<int> unremapped_id = GetUnRemappedCameraId(camera_id);
  if (!unremapped_id) {
    camera_info->reset();
    return -EINVAL;
  }
  LOGF(INFO) << "From remap camera id " << camera_id << " to "
             << *unremapped_id;
  int32_t ret = CameraHalAdapter::GetCameraInfo(*unremapped_id, camera_info,
                                                camera_client_type);
  if (ret != 0) {
    return ret;
  }
  if ((*camera_info)->conflicting_devices) {
    std::vector<std::string> conflicting_devices;
    for (const std::string& id_str : *(*camera_info)->conflicting_devices) {
      std::optional<int> remapped_id = GetRemappedCameraId(std::stoi(id_str));
      if (remapped_id) {
        conflicting_devices.push_back(std::to_string(*remapped_id));
      }
    }
    (*camera_info)->conflicting_devices = std::move(conflicting_devices);
  }
  return 0;
}

int32_t CameraHalTestAdapter::SetTorchMode(int32_t camera_id, bool enabled) {
  std::optional<int> unremapped_id = GetUnRemappedCameraId(camera_id);
  if (!unremapped_id) {
    return -EINVAL;
  }
  LOGF(INFO) << "From remap camera id " << camera_id << " to "
             << *unremapped_id;
  return CameraHalAdapter::SetTorchMode(*unremapped_id, enabled);
}

void CameraHalTestAdapter::StartOnThread(
    base::OnceCallback<void(bool)> callback) {
  auto future = cros::Future<bool>::Create(nullptr);
  CameraHalAdapter::StartOnThread(cros::GetFutureCallback(future));

  if (!future.get()) {
    std::move(callback).Run(false);
    return;
  }

  for (int cam_id = 0; cam_id < CameraHalAdapter::GetNumberOfCameras();
       cam_id++) {
    camera_module_t* m;
    int internal_id;
    std::tie(m, internal_id) = CameraHalAdapter::GetInternalModuleAndId(cam_id);

    camera_info_t info;
    int ret = m->get_camera_info(internal_id, &info);
    if (ret != 0) {
      LOGF(ERROR) << "Failed to get info of camera " << cam_id;
      std::move(callback).Run(false);
      return;
    }

    if ((info.facing == CAMERA_FACING_BACK && enable_back_) ||
        (info.facing == CAMERA_FACING_FRONT && enable_front_)) {
      LOGF(INFO) << "Remap camera id " << cam_id << "->"
                 << enable_camera_ids_.size();
      enable_camera_ids_.push_back(cam_id);
    } else {
      LOGF(INFO) << "Filter out camera " << internal_id << " facing "
                 << info.facing << " of module " << m->common.name;
    }
  }
  LOGF(INFO) << "Enable total " << enable_camera_ids_.size() << " cameras";
  std::move(callback).Run(true);
}

void CameraHalTestAdapter::NotifyCameraDeviceStatusChange(
    CameraModuleCallbacksAssociatedDelegate* delegate,
    int camera_id,
    camera_device_status_t status) {
  std::optional<int> remapped_id = GetRemappedCameraId(camera_id);
  if (remapped_id) {
    LOGF(INFO) << "Remap external camera id " << camera_id << "->"
               << *remapped_id;
    CameraHalAdapter::NotifyCameraDeviceStatusChange(delegate, *remapped_id,
                                                     status);
  }
}

void CameraHalTestAdapter::NotifyTorchModeStatusChange(
    CameraModuleCallbacksAssociatedDelegate* delegate,
    int camera_id,
    torch_mode_status_t status) {
  std::optional<int> remapped_id = GetRemappedCameraId(camera_id);
  if (remapped_id) {
    CameraHalAdapter::NotifyTorchModeStatusChange(delegate, *remapped_id,
                                                  status);
  }
}

std::optional<int> CameraHalTestAdapter::GetUnRemappedCameraId(int camera_id) {
  if (camera_id < 0) {
    LOGF(ERROR) << "Invalid remapped camera id: " << camera_id;
    return {};
  }
  if (camera_id < enable_camera_ids_.size()) {
    return enable_camera_ids_[camera_id];
  } else if (enable_external_) {
    return camera_id - GetNumberOfCameras() +
           CameraHalAdapter::GetNumberOfCameras();
  } else {
    return {};
  }
}

std::optional<int> CameraHalTestAdapter::GetRemappedCameraId(int camera_id) {
  if (camera_id < 0) {
    LOGF(ERROR) << "Invalid unremapped camera id: " << camera_id;
    return {};
  }
  if (camera_id < CameraHalAdapter::GetNumberOfCameras()) {
    auto it = std::find(enable_camera_ids_.begin(), enable_camera_ids_.end(),
                        camera_id);
    return it != enable_camera_ids_.end() ? it - enable_camera_ids_.begin()
                                          : std::optional<int>{};
  } else if (enable_external_) {
    return camera_id - CameraHalAdapter::GetNumberOfCameras() +
           GetNumberOfCameras();
  } else {
    return {};
  }
}

}  // namespace cros
