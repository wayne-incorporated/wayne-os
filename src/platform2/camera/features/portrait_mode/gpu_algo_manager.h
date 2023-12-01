/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_PORTRAIT_MODE_GPU_ALGO_MANAGER_H_
#define CAMERA_FEATURES_PORTRAIT_MODE_GPU_ALGO_MANAGER_H_

#include <map>
#include <memory>
#include <vector>

#include <base/functional/callback.h>
#include <base/synchronization/lock.h>

#include "cros-camera/camera_algorithm_bridge.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"

namespace cros {

class GPUAlgoManager : public camera_algorithm_callback_ops_t {
 public:
  GPUAlgoManager(const GPUAlgoManager&) = delete;
  GPUAlgoManager& operator=(const GPUAlgoManager&) = delete;

  static GPUAlgoManager* GetInstance(CameraMojoChannelManagerToken* token);

  int32_t RegisterBuffer(int buffer_fd);

  void Request(const std::vector<uint8_t>& req_header,
               int32_t buffer_handle,
               base::OnceCallback<void(uint32_t, int32_t)> cb);

  void DeregisterBuffers(const std::vector<int32_t>& buffer_handles);

 private:
  explicit GPUAlgoManager(CameraMojoChannelManagerToken* token);

  ~GPUAlgoManager() = default;

  static void ReturnCallbackForwarder(
      const camera_algorithm_callback_ops_t* callback_ops,
      uint32_t req_id,
      uint32_t status,
      int32_t buffer_handle);

  void ReturnCallback(uint32_t req_id, uint32_t status, int32_t buffer_handle);

  std::unique_ptr<CameraAlgorithmBridge> bridge_;

  // Lock to protect |req_id_| and |cb_map_|
  base::Lock lock_;

  uint32_t req_id_;

  std::map<uint32_t, base::OnceCallback<void(uint32_t, int32_t)>> cb_map_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_PORTRAIT_MODE_GPU_ALGO_MANAGER_H_
