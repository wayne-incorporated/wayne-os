/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <utility>
#include <vector>

#include "common/camera_algorithm_callback_ops_impl.h"

#include "cros-camera/common.h"

#include <base/check.h>

namespace cros {

CameraAlgorithmCallbackOpsImpl::CameraAlgorithmCallbackOpsImpl(
    scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
    const camera_algorithm_callback_ops_t* callback_ops)
    : receiver_(this),
      ipc_task_runner_(std::move(ipc_task_runner)),
      callback_ops_(callback_ops) {}

void CameraAlgorithmCallbackOpsImpl::Return(uint32_t req_id,
                                            uint32_t status,
                                            int32_t buffer_handle) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  DCHECK(callback_ops_);
  DCHECK(callback_ops_->return_callback);

  callback_ops_->return_callback(callback_ops_, req_id, status, buffer_handle);
}

void CameraAlgorithmCallbackOpsImpl::Update(
    uint32_t upd_id,
    const std::vector<uint8_t>& upd_header,
    mojo::ScopedHandle buffer_fd) {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  DCHECK(callback_ops_);

  if (callback_ops_->update == nullptr) {
    LOGF(FATAL) << "Algorithm calls unregistered update callback";
    return;
  }
  base::ScopedPlatformFile fd;
  MojoResult mojo_result = mojo::UnwrapPlatformFile(std::move(buffer_fd), &fd);
  if (mojo_result != MOJO_RESULT_OK) {
    LOGF(ERROR) << "Failed to unwrap handle: " << mojo_result;
    return;
  }
  callback_ops_->update(callback_ops_, upd_id, upd_header.data(),
                        upd_header.size(), fd.release());
}

mojo::PendingRemote<mojom::CameraAlgorithmCallbackOps>
CameraAlgorithmCallbackOpsImpl::CreatePendingRemote() {
  DCHECK(ipc_task_runner_->BelongsToCurrentThread());
  return receiver_.BindNewPipeAndPassRemote();
}

}  // namespace cros
