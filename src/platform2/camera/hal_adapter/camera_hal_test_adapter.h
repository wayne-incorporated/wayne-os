/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_ADAPTER_CAMERA_HAL_TEST_ADAPTER_H_
#define CAMERA_HAL_ADAPTER_CAMERA_HAL_TEST_ADAPTER_H_

#include <optional>
#include <utility>
#include <vector>

#include <hardware/camera3.h>

#include "hal_adapter/camera_hal_adapter.h"

namespace cros {

class CameraHalTestAdapter : public CameraHalAdapter {
 public:
  CameraHalTestAdapter(
      std::vector<std::pair<camera_module_t*, cros_camera_hal_t*>>
          camera_interfaces,
      CameraMojoChannelManagerToken* token,
      CameraActivityCallback activity_callback,
      bool enable_front,
      bool enable_back,
      bool enable_external);

  CameraHalTestAdapter(const CameraHalTestAdapter&) = delete;
  CameraHalTestAdapter& operator=(const CameraHalTestAdapter&) = delete;

  ~CameraHalTestAdapter() override = default;

  int32_t OpenDevice(
      int32_t camera_id,
      mojo::PendingReceiver<mojom::Camera3DeviceOps> device_ops_receiver,
      mojom::CameraClientType camera_client_type) override;

  int32_t GetNumberOfCameras() override;

  int32_t GetCameraInfo(int32_t camera_id,
                        mojom::CameraInfoPtr* camera_info,
                        mojom::CameraClientType camera_client_type) override;

  int32_t SetTorchMode(int32_t camera_id, bool enabled) override;

 protected:
  void StartOnThread(base::OnceCallback<void(bool)> callback) override;

  void NotifyCameraDeviceStatusChange(
      CameraModuleCallbacksAssociatedDelegate* delegate,
      int camera_id,
      camera_device_status_t status) override;

  void NotifyTorchModeStatusChange(
      CameraModuleCallbacksAssociatedDelegate* delegate,
      int camera_id,
      torch_mode_status_t status) override;

 private:
  bool enable_front_, enable_back_, enable_external_;

  // Id of enabled cameras assigned by SuperHAL. |CameraHalTestAdapter| will
  // reassign new id exposed to framework based on its index in this vector.
  std::vector<int> enable_camera_ids_;

  std::optional<int32_t> GetRemappedCameraId(int camera_id);

  std::optional<int32_t> GetUnRemappedCameraId(int camera_id);
};

}  // namespace cros

#endif  // CAMERA_HAL_ADAPTER_CAMERA_HAL_TEST_ADAPTER_H_
