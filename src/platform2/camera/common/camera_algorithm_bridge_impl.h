/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_ALGORITHM_BRIDGE_IMPL_H_
#define CAMERA_COMMON_CAMERA_ALGORITHM_BRIDGE_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include <base/memory/weak_ptr.h>
#include <base/synchronization/lock.h>
#include <base/threading/thread.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "common/camera_algorithm_callback_ops_impl.h"
#include "common/camera_algorithm_ops_impl.h"
#include "cros-camera/camera_algorithm.h"
#include "cros-camera/camera_algorithm_bridge.h"
#include "cros-camera/camera_mojo_channel_manager.h"
#include "cros-camera/future.h"

namespace cros {

// This is the implementation of CameraAlgorithmBridge interface. It is used
// by the camera HAL process.

class CameraAlgorithmBridgeImpl : public CameraAlgorithmBridge {
 public:
  CameraAlgorithmBridgeImpl(CameraAlgorithmBackend backend,
                            CameraMojoChannelManager* mojo_manager);
  CameraAlgorithmBridgeImpl(const CameraAlgorithmBridgeImpl&) = delete;
  CameraAlgorithmBridgeImpl& operator=(const CameraAlgorithmBridgeImpl&) =
      delete;

  ~CameraAlgorithmBridgeImpl() override;

  // This method registers a callback function for buffer handle return.
  int32_t Initialize(
      const camera_algorithm_callback_ops_t* callback_ops) override;

  // Register a buffer to the camera algorithm library and gets
  // the handle associated with it.
  int32_t RegisterBuffer(int buffer_fd) override;

  // Post a request for the camera algorithm library to process the
  // given buffer.
  void Request(uint32_t req_id,
               const std::vector<uint8_t>& req_header,
               int32_t buffer_handle) override;

  // Deregisters buffers to the camera algorithm library.
  void DeregisterBuffers(const std::vector<int32_t>& buffer_handles) override;

  // Returns the result for an update from the camera algorithm library.
  void UpdateReturn(uint32_t upd_id, uint32_t status, int buffer_fd) override;

 private:
  // IPCBridge wraps all the IPC-related calls. Most of its methods should/will
  // be run on IPC thread.
  class IPCBridge {
   public:
    IPCBridge(CameraAlgorithmBackend backend,
              CameraMojoChannelManager* mojo_manager);

    // It should only be triggered on IPC thread to ensure thread-safety.
    ~IPCBridge();

    void Initialize(const camera_algorithm_callback_ops_t* callback_ops,
                    base::OnceCallback<void(int32_t)> cb);

    void RegisterBuffer(int buffer_fd, base::OnceCallback<void(int32_t)> cb);

    void Request(uint32_t req_id,
                 std::vector<uint8_t> req_header,
                 int32_t buffer_handle);

    void DeregisterBuffers(std::vector<int32_t> buffer_handles);

    void UpdateReturn(uint32_t upd_id, uint32_t status, int buffer_fd);

    void OnConnectionError();

    void Destroy();

    // Gets a weak pointer of the IPCBridge. This method can be called on
    // non-IPC thread.
    base::WeakPtr<IPCBridge> GetWeakPtr();

   private:
    // The algorithm backend this bridge is created for.
    CameraAlgorithmBackend algo_backend_;

    // Return callback registered by HAL
    const camera_algorithm_callback_ops_t* callback_ops_;

    // Proxy to remote CameraAlgorithmOps interface implementation.
    mojo::Remote<mojom::CameraAlgorithmOps> remote_;

    // Pointer to CameraAlgorithmCallbackOpss interface implementation.
    std::unique_ptr<CameraAlgorithmCallbackOpsImpl> cb_impl_;

    // Camera Mojo channel manager.
    // We use it to create JpegEncodeAccelerator Mojo channel.
    CameraMojoChannelManager* mojo_manager_;

    // The Mojo IPC task runner.
    const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;

    base::WeakPtrFactory<IPCBridge> weak_ptr_factory_{this};
  };

  CameraMojoChannelManager* mojo_manager_;

  // Store observers for future locks
  cros::CancellationRelay relay_;

  // The instance which deals with the IPC-related calls. It should always run
  // and be deleted on IPC thread.
  std::unique_ptr<IPCBridge> ipc_bridge_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_CAMERA_ALGORITHM_BRIDGE_IMPL_H_
