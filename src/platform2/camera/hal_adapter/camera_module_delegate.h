/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_ADAPTER_CAMERA_MODULE_DELEGATE_H_
#define CAMERA_HAL_ADAPTER_CAMERA_MODULE_DELEGATE_H_

#include "camera/mojo/camera3.mojom.h"
#include "camera/mojo/camera_common.mojom.h"
#include "camera/mojo/cros_camera_service.mojom.h"
#include "common/utils/cros_camera_mojo_utils.h"

namespace cros {

class CameraHalAdapter;

class CameraModuleDelegate
    : public internal::MojoReceiver<mojom::CameraModule> {
 public:
  CameraModuleDelegate(CameraHalAdapter* camera_hal_adapter,
                       scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                       mojom::CameraClientType camera_client_type);

  CameraModuleDelegate(const CameraModuleDelegate&) = delete;
  CameraModuleDelegate& operator=(const CameraModuleDelegate&) = delete;

  ~CameraModuleDelegate() override;

 private:
  void OpenDevice(
      int32_t camera_id,
      mojo::PendingReceiver<mojom::Camera3DeviceOps> device_ops_receiver,
      OpenDeviceCallback callback) override;

  void GetNumberOfCameras(GetNumberOfCamerasCallback callback) override;

  void GetCameraInfo(int32_t camera_id,
                     GetCameraInfoCallback callback) override;

  // TODO(b/169324225): Deprecated. Use SetCallbacksAssociated instead.
  void SetCallbacks(mojo::PendingRemote<mojom::CameraModuleCallbacks> callbacks,
                    SetCallbacksCallback callback) override;

  void SetTorchMode(int32_t camera_id,
                    bool enabled,
                    SetTorchModeCallback callback) override;

  void Init(InitCallback callback) override;

  void GetVendorTagOps(
      mojo::PendingReceiver<mojom::VendorTagOps> vendor_tag_ops_receiver,
      GetVendorTagOpsCallback callback) override;

  void SetCallbacksAssociated(
      mojo::PendingAssociatedRemote<mojom::CameraModuleCallbacks> callbacks,
      SetCallbacksAssociatedCallback callback) override;

  CameraHalAdapter* camera_hal_adapter_;
  mojom::CameraClientType camera_client_type_;
};

}  // namespace cros

#endif  // CAMERA_HAL_ADAPTER_CAMERA_MODULE_DELEGATE_H_
