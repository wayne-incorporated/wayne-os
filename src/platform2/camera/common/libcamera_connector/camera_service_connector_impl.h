/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_LIBCAMERA_CONNECTOR_CAMERA_SERVICE_CONNECTOR_IMPL_H_
#define CAMERA_COMMON_LIBCAMERA_CONNECTOR_CAMERA_SERVICE_CONNECTOR_IMPL_H_

#include <memory>

#include <base/functional/bind.h>
#include <base/sequence_checker.h>
#include <base/synchronization/atomic_flag.h>
#include <base/threading/thread.h>
#include <base/time/time.h>
#include <base/unguessable_token.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "camera/mojo/cros_camera_service.mojom.h"
#include "common/libcamera_connector/camera_client.h"
#include "cros-camera/camera_service_connector.h"

namespace cros {

class CameraServiceConnector {
 public:
  CameraServiceConnector();

  static CameraServiceConnector* GetInstance();

  // Initializes the connection to camera HAL dispatcher and registers the
  // camera HAL client. Must be called before any other functions.
  int Init(const cros_cam_init_option_t* option);

  // Terminates camera HAL client, all connections and threads.
  int Exit();

  // Sets the callback for camera info changes and fires |callback| with the
  // info of the cameras currently present.
  // TODO(b/151047930): Subscribe to hotplug events once external camera support
  // is added.
  int GetCameraInfo(cros_cam_get_cam_info_cb_t callback, void* context);

  // Starts capturing with the given parameters.
  int StartCapture(const cros_cam_capture_request_t* request,
                   cros_cam_capture_cb_t callback,
                   void* context);

  // Stops capturing. Waits for the ongoing capture callback if there is any
  // underway.
  int StopCapture(int id);

 private:
  using ConnectDispatcherCallback = base::OnceCallback<void()>;

  // Registers the camera HAL client to camera HAL dispatcher.
  void RegisterClient(
      mojo::PendingRemote<mojom::CameraHalClient> camera_hal_client,
      IntOnceCallback on_registered_callback);

  void RegisterClientOnThread(
      mojo::PendingRemote<mojom::CameraHalClient> camera_hal_client,
      IntOnceCallback on_registered_callback);

  void OnRegisteredClient(IntOnceCallback on_registered_callback,
                          int32_t result);

  void InitOnThread(IntOnceCallback init_callback);

  void OnDispatcherError();

  base::Thread ipc_thread_;
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;
  mojo::Remote<mojom::CameraHalDispatcher> dispatcher_;
  std::unique_ptr<CameraClient> camera_client_;
  base::UnguessableToken token_;

  base::AtomicFlag initialized_;

  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace cros

#endif  // CAMERA_COMMON_LIBCAMERA_CONNECTOR_CAMERA_SERVICE_CONNECTOR_IMPL_H_
