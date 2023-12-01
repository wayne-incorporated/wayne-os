/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_ALGORITHM_OPS_IMPL_H_
#define CAMERA_COMMON_CAMERA_ALGORITHM_OPS_IMPL_H_

#include <vector>

#include <base/threading/thread.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/algorithm/camera_algorithm.mojom.h"
#include "cros-camera/camera_algorithm.h"

namespace cros {

// This is the implementation of CameraAlgorithmOps mojo interface. It is used
// by the sandboxed camera algorithm library process.

class CameraAlgorithmOpsImpl : public mojom::CameraAlgorithmOps,
                               private camera_algorithm_callback_ops_t {
 public:
  CameraAlgorithmOpsImpl();
  CameraAlgorithmOpsImpl(const CameraAlgorithmOpsImpl&) = delete;
  CameraAlgorithmOpsImpl& operator=(const CameraAlgorithmOpsImpl&) = delete;

  // Get singleton instance
  static CameraAlgorithmOpsImpl* GetInstance();

  // Completes a receiver by removing the message pipe endpoint from
  // |pending_receiver| and binding it to the interface implementation.
  bool Bind(mojo::PendingReceiver<mojom::CameraAlgorithmOps> pending_receiver,
            camera_algorithm_ops_t* cam_algo,
            scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner,
            base::OnceClosure ipc_lost_handler);

  // Unbinds the underlying pipe.
  void Unbind();

  // Implementation of mojom::CameraAlgorithmOps::Initialize interface
  void Initialize(
      mojo::PendingRemote<mojom::CameraAlgorithmCallbackOps> callbacks,
      InitializeCallback callback) override;

  // Implementation of mojom::CameraAlgorithmOps::RegisterBuffer interface
  void RegisterBuffer(mojo::ScopedHandle buffer_fd,
                      RegisterBufferCallback callback) override;

  // Implementation of mojom::CameraAlgorithmOps::Request interface
  void Request(uint32_t req_id,
               const std::vector<uint8_t>& req_headers,
               int32_t buffer_handle) override;

  // Implementation of mojom::CameraAlgorithmOps::DeregisterBuffers interface
  void DeregisterBuffers(const std::vector<int32_t>& buffer_handles) override;

  // Implementation of mojom::CameraAlgorithmOps::UpdateReturn interface
  void UpdateReturn(uint32_t upd_id,
                    uint32_t status,
                    mojo::ScopedHandle buffer_fd) override;

  // Implementation of mojom::CameraAlgorithmOps::Deinitialize interface
  void Deinitialize() override;

 private:
  ~CameraAlgorithmOpsImpl() override = default;

  static void ReturnCallbackForwarder(
      const camera_algorithm_callback_ops_t* callback_ops,
      uint32_t req_id,
      uint32_t status,
      int32_t buffer_handle);

  void ReturnCallbackOnIPCThread(uint32_t req_id,
                                 uint32_t status,
                                 int32_t buffer_handle);

  static void UpdateForwarder(
      const camera_algorithm_callback_ops_t* callback_ops,
      uint32_t upd_id,
      const uint8_t upd_header[],
      uint32_t size,
      int buffer_fd);

  void UpdateOnIPCThread(uint32_t upd_id,
                         const std::vector<uint8_t>& upd_header,
                         int buffer_fd);

  // Receiver of CameraAlgorithmOps interface to message pipe
  mojo::Receiver<mojom::CameraAlgorithmOps> receiver_;

  // Interface of camera algorithm library
  camera_algorithm_ops_t* cam_algo_;

  // Pointer to self for ReturnCallbackForwarder to get the singleton instance
  static CameraAlgorithmOpsImpl* singleton_;

  // Task runner of |CameraAlgorithmAdapter::ipc_thread_|
  scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;

  // Pointer to local proxy of remote CameraAlgorithmCallback interface
  // implementation
  mojo::Remote<mojom::CameraAlgorithmCallbackOps> callback_ops_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_CAMERA_ALGORITHM_OPS_IMPL_H_
