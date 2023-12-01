/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/portrait_mode/gpu_algo_manager.h"

#include <utility>
#include <vector>

#include <base/containers/contains.h>
#include <base/logging.h>

#include "cros-camera/common.h"

namespace cros {

// static
GPUAlgoManager* GPUAlgoManager::GetInstance(
    CameraMojoChannelManagerToken* token) {
  static GPUAlgoManager* m = new GPUAlgoManager(token);
  if (!m->bridge_) {
    return nullptr;
  }
  return m;
}

GPUAlgoManager::GPUAlgoManager(CameraMojoChannelManagerToken* token)
    : camera_algorithm_callback_ops_t{}, req_id_(0) {
  return_callback = GPUAlgoManager::ReturnCallbackForwarder;
  bridge_ = cros::CameraAlgorithmBridge::CreateInstance(
      cros::CameraAlgorithmBackend::kGoogleGpu, token);
  if (!bridge_ || bridge_->Initialize(this) != 0) {
    LOGF(WARNING) << "Failed to initialize camera GPU algorithm bridge";
    bridge_ = nullptr;
  }
}

int32_t GPUAlgoManager::RegisterBuffer(int buffer_fd) {
  return bridge_->RegisterBuffer(buffer_fd);
}

void GPUAlgoManager::Request(const std::vector<uint8_t>& req_header,
                             int32_t buffer_handle,
                             base::OnceCallback<void(uint32_t, int32_t)> cb) {
  uint32_t req_id = 0;
  {
    base::AutoLock l(lock_);
    req_id = req_id_++;
    cb_map_[req_id] = std::move(cb);
  }
  bridge_->Request(req_id, req_header, buffer_handle);
}

void GPUAlgoManager::DeregisterBuffers(
    const std::vector<int32_t>& buffer_handles) {
  bridge_->DeregisterBuffers(buffer_handles);
}

// static
void GPUAlgoManager::ReturnCallbackForwarder(
    const camera_algorithm_callback_ops_t* callback_ops,
    uint32_t req_id,
    uint32_t status,
    int32_t buffer_handle) {
  if (callback_ops) {
    auto self = const_cast<GPUAlgoManager*>(
        static_cast<const GPUAlgoManager*>(callback_ops));
    self->ReturnCallback(req_id, status, buffer_handle);
  }
}

void GPUAlgoManager::ReturnCallback(uint32_t req_id,
                                    uint32_t status,
                                    int32_t buffer_handle) {
  base::OnceCallback<void(uint32_t, int32_t)> cb;
  {
    base::AutoLock l(lock_);
    if (!base::Contains(cb_map_, req_id)) {
      LOGF(ERROR) << "Failed to find callback for request " << req_id;
      return;
    }
    cb = std::move(cb_map_.at(req_id));
    cb_map_.erase(req_id);
  }
  std::move(cb).Run(status, buffer_handle);
}

}  // namespace cros
