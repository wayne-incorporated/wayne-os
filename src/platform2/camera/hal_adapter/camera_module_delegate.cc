/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal_adapter/camera_module_delegate.h"

#include <utility>

#include "cros-camera/common.h"
#include "hal_adapter/camera_hal_adapter.h"

#include <base/check.h>

namespace cros {

CameraModuleDelegate::CameraModuleDelegate(
    CameraHalAdapter* camera_hal_adapter,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    mojom::CameraClientType camera_client_type)
    : internal::MojoReceiver<mojom::CameraModule>(task_runner),
      camera_hal_adapter_(camera_hal_adapter),
      camera_client_type_(camera_client_type) {}

CameraModuleDelegate::~CameraModuleDelegate() {}

void CameraModuleDelegate::OpenDevice(
    int32_t camera_id,
    mojo::PendingReceiver<mojom::Camera3DeviceOps> device_ops_receiver,
    OpenDeviceCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(camera_hal_adapter_->OpenDevice(
      camera_id, std::move(device_ops_receiver), camera_client_type_));
}

void CameraModuleDelegate::GetNumberOfCameras(
    GetNumberOfCamerasCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(camera_hal_adapter_->GetNumberOfCameras());
}

void CameraModuleDelegate::GetCameraInfo(int32_t camera_id,
                                         GetCameraInfoCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  mojom::CameraInfoPtr camera_info;
  int32_t result = camera_hal_adapter_->GetCameraInfo(camera_id, &camera_info,
                                                      camera_client_type_);
  std::move(callback).Run(result, std::move(camera_info));
}

void CameraModuleDelegate::SetCallbacks(
    mojo::PendingRemote<mojom::CameraModuleCallbacks> callbacks,
    SetCallbacksCallback callback) {
  LOGF(ERROR) << "CameraModuleDelegate::SetCallbacks() is deprecated";
  std::move(callback).Run(-ENODEV);
}

void CameraModuleDelegate::SetTorchMode(int32_t camera_id,
                                        bool enabled,
                                        SetTorchModeCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(
      camera_hal_adapter_->SetTorchMode(camera_id, enabled));
}

void CameraModuleDelegate::Init(InitCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(camera_hal_adapter_->Init());
}

void CameraModuleDelegate::GetVendorTagOps(
    mojo::PendingReceiver<mojom::VendorTagOps> vendor_tag_ops_receiver,
    GetVendorTagOpsCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  camera_hal_adapter_->GetVendorTagOps(std::move(vendor_tag_ops_receiver));
  std::move(callback).Run();
}

void CameraModuleDelegate::SetCallbacksAssociated(
    mojo::PendingAssociatedRemote<mojom::CameraModuleCallbacks> callbacks,
    SetCallbacksAssociatedCallback callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  std::move(callback).Run(
      camera_hal_adapter_->SetCallbacks(std::move(callbacks)));
}

}  // namespace cros
