/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal_adapter/camera3_callback_ops_delegate.h"

#include <inttypes.h>
#include <utility>

#include <base/check.h>
#include <base/functional/bind.h>
#include <base/functional/callback_helpers.h>
#include <base/strings/stringprintf.h>

#include "cros-camera/common.h"
#include "cros-camera/future.h"
#include "hal_adapter/camera_device_adapter.h"
#include "hal_adapter/camera_trace_event.h"

namespace cros {

Camera3CallbackOpsDelegate::Camera3CallbackOpsDelegate(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner)
    : internal::MojoRemote<mojom::Camera3CallbackOps>(task_runner) {}

void Camera3CallbackOpsDelegate::ProcessCaptureResult(
    mojom::Camera3CaptureResultPtr result) {
  task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&Camera3CallbackOpsDelegate::ProcessCaptureResultOnThread,
                     base::AsWeakPtr(this), std::move(result)));
}

void Camera3CallbackOpsDelegate::Notify(mojom::Camera3NotifyMsgPtr msg) {
  task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&Camera3CallbackOpsDelegate::NotifyOnThread,
                                base::AsWeakPtr(this), std::move(msg)));
}

void Camera3CallbackOpsDelegate::ProcessCaptureResultOnThread(
    mojom::Camera3CaptureResultPtr result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER("frame_number", result->frame_number);

  remote_->ProcessCaptureResult(std::move(result));
}

void Camera3CallbackOpsDelegate::NotifyOnThread(
    mojom::Camera3NotifyMsgPtr msg) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HAL_ADAPTER();

  remote_->Notify(std::move(msg));
}

}  // end of namespace cros
