/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_ADAPTER_CAMERA_MODULE_CALLBACKS_ASSOCIATED_DELEGATE_H_
#define CAMERA_HAL_ADAPTER_CAMERA_MODULE_CALLBACKS_ASSOCIATED_DELEGATE_H_

#include "camera/mojo/camera_common.mojom.h"
#include "common/utils/cros_camera_mojo_utils.h"
#include "cros-camera/future.h"

namespace cros {

class CameraModuleCallbacksAssociatedDelegate
    : public internal::MojoAssociatedRemote<mojom::CameraModuleCallbacks> {
 public:
  explicit CameraModuleCallbacksAssociatedDelegate(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner);

  CameraModuleCallbacksAssociatedDelegate(
      const CameraModuleCallbacksAssociatedDelegate&) = delete;
  CameraModuleCallbacksAssociatedDelegate& operator=(
      const CameraModuleCallbacksAssociatedDelegate&) = delete;

  ~CameraModuleCallbacksAssociatedDelegate() = default;

  void CameraDeviceStatusChange(int camera_id, int new_status);

  void TorchModeStatusChange(int camera_id, int new_status);

 private:
  void CameraDeviceStatusChangeOnThread(int camera_id,
                                        int new_status,
                                        base::OnceClosure callback);

  void TorchModeStatusChangeOnThread(int camera_id,
                                     int new_status,
                                     base::OnceClosure callback);

  cros::CancellationRelay relay_;
};

}  // namespace cros

#endif  // CAMERA_HAL_ADAPTER_CAMERA_MODULE_CALLBACKS_ASSOCIATED_DELEGATE_H_
