/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal_adapter/camera_module_callbacks_associated_delegate.h"

#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>

#include "cros-camera/common.h"
#include "cros-camera/future.h"

namespace cros {

CameraModuleCallbacksAssociatedDelegate::
    CameraModuleCallbacksAssociatedDelegate(
        scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : internal::MojoAssociatedRemote<mojom::CameraModuleCallbacks>(
          task_runner) {}

void CameraModuleCallbacksAssociatedDelegate::CameraDeviceStatusChange(
    int camera_id, int new_status) {
  auto future = cros::Future<void>::Create(&relay_);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&CameraModuleCallbacksAssociatedDelegate::
                                    CameraDeviceStatusChangeOnThread,
                                base::AsWeakPtr(this), camera_id, new_status,
                                cros::GetFutureCallback(future)));
  future->Wait();
}

void CameraModuleCallbacksAssociatedDelegate::TorchModeStatusChange(
    int camera_id, int new_status) {
  auto future = cros::Future<void>::Create(&relay_);
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&CameraModuleCallbacksAssociatedDelegate::
                                    TorchModeStatusChangeOnThread,
                                base::AsWeakPtr(this), camera_id, new_status,
                                cros::GetFutureCallback(future)));
  future->Wait();
}

void CameraModuleCallbacksAssociatedDelegate::CameraDeviceStatusChangeOnThread(
    int camera_id, int new_status, base::OnceClosure callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  remote_->CameraDeviceStatusChange(
      camera_id, static_cast<mojom::CameraDeviceStatus>(new_status));
  std::move(callback).Run();
}

void CameraModuleCallbacksAssociatedDelegate::TorchModeStatusChangeOnThread(
    int camera_id, int new_status, base::OnceClosure callback) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  remote_->TorchModeStatusChange(
      camera_id, static_cast<mojom::TorchModeStatus>(new_status));
  std::move(callback).Run();
}

}  // namespace cros
