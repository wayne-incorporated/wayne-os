/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_ALGORITHM_ADAPTER_H_
#define CAMERA_COMMON_CAMERA_ALGORITHM_ADAPTER_H_

#include <memory>
#include <string>

#include <base/files/scoped_file.h>
#include <base/threading/thread.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "common/camera_algorithm_ops_impl.h"
#include "cros-camera/future.h"

namespace cros {

// This class loads and adapts the functions of camera algorithm. It runs in
// the sandboxed camera algorithm process.

class CameraAlgorithmAdapter {
 public:
  CameraAlgorithmAdapter();
  CameraAlgorithmAdapter(const CameraAlgorithmAdapter&) = delete;
  CameraAlgorithmAdapter& operator=(const CameraAlgorithmAdapter&) = delete;

  ~CameraAlgorithmAdapter();

  // Build up IPC and load the camera algorithm library. This method returns
  // when the IPC connection is lost.
  void Run(std::string pipe_name, base::ScopedFD channel);

 private:
  void InitializeOnIpcThread(std::string pipe_name, base::ScopedFD channel);

  void DestroyOnIpcThread();

  // Pointer to CameraAlgorithmOps interface implementation.
  CameraAlgorithmOpsImpl* algo_impl_;
  bool is_algo_impl_bound_;

  // Handle of the camera algorithm library.
  void* algo_dll_handle_;

  // Thread for IPC chores
  base::Thread ipc_thread_;
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  // Callback to handle IPC channel lost event
  base::OnceCallback<void(void)> ipc_lost_cb_;

  // Store observers for future locks
  cros::CancellationRelay relay_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_CAMERA_ALGORITHM_ADAPTER_H_
