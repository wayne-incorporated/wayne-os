/*
 * Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_ADAPTER_CAMERA_HAL_SERVER_IMPL_H_
#define CAMERA_HAL_ADAPTER_CAMERA_HAL_SERVER_IMPL_H_

#include <memory>
#include <vector>

#include <base/files/file_path.h>
#include <base/synchronization/lock.h>
#include <base/task/single_thread_task_runner.h>
#include <base/thread_annotations.h>
#include <base/threading/thread_checker.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/receiver.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/cros_camera_service.mojom.h"
#include "camera/mojo/effects/effects_pipeline.mojom.h"
#include "cros-camera/cros_camera_hal.h"
#include "hal_adapter/camera_hal_adapter.h"

namespace cros {

class CameraMojoChannelManager;

// CameraHalServerImpl is the implementation of the CameraHalServer Mojo
// interface.  It hosts the camera HAL v3 adapter and registers itself to the
// CameraHalDispatcher Mojo proxy in started by Chrome.  Camera clients such
// as Chrome VideoCaptureDeviceFactory and Android cameraserver process connect
// to the CameraHalDispatcher to ask for camera service; CameraHalDispatcher
// proxies the service requests to CameraHalServerImpl.
class CameraHalServerImpl {
 public:
  CameraHalServerImpl();
  CameraHalServerImpl(const CameraHalServerImpl&) = delete;
  CameraHalServerImpl& operator=(const CameraHalServerImpl&) = delete;

  ~CameraHalServerImpl();

  // Initializes the threads and start monitoring the unix domain socket file
  // created by Chrome.
  void Start();

 private:
  using SetPrivacySwitchCallback =
      base::OnceCallback<void(PrivacySwitchStateChangeCallback)>;

  // IPCBridge wraps all the IPC-related calls. Most of its methods should/will
  // be run on IPC thread.
  class IPCBridge : public mojom::CameraHalServer {
   public:
    IPCBridge(CameraHalServerImpl* camera_hal_server,
              CameraMojoChannelManager* mojo_manager);

    ~IPCBridge() override;

    void Start(CameraHalAdapter* camera_hal_adapter,
               SetPrivacySwitchCallback set_privacy_switch_callback);

    // CameraHalServer Mojo interface implementation.

    void CreateChannel(
        mojo::PendingReceiver<mojom::CameraModule> camera_module_receiver,
        mojom::CameraClientType camera_client_type) override;

    void SetTracingEnabled(bool enabled) override;

    void SetAutoFramingState(mojom::CameraAutoFramingState state) override;

    void GetCameraSWPrivacySwitchState(
        mojom::CameraHalServer::GetCameraSWPrivacySwitchStateCallback callback)
        override;

    void SetCameraSWPrivacySwitchState(
        mojom::CameraPrivacySwitchState state) override;

    void GetAutoFramingSupported(
        mojom::CameraHalServer::GetAutoFramingSupportedCallback callback)
        override;

    void SetCameraEffect(
        mojom::EffectsConfigPtr config,
        mojom::CameraHalServer::SetCameraEffectCallback callback) override;
    void NotifyCameraActivityChange(int32_t camera_id,
                                    bool opened,
                                    mojom::CameraClientType type);

    // Gets a weak pointer of the IPCBridge. This method can be called on
    // non-IPC thread.
    base::WeakPtr<IPCBridge> GetWeakPtr();

   private:
    // Triggered when the HAL server is registered.
    void OnServerRegistered(
        SetPrivacySwitchCallback set_privacy_switch_callback,
        int32_t result,
        mojo::PendingRemote<mojom::CameraHalServerCallbacks> callbacks);

    // Connection error handler for the Mojo connection to CameraHalDispatcher.
    void OnServiceMojoChannelError();

    // Triggers when the camera privacy switch status changed.
    void OnPrivacySwitchStatusChanged(int camera_id, PrivacySwitchState state);

    CameraHalServerImpl* camera_hal_server_;

    CameraMojoChannelManager* mojo_manager_;

    // The Mojo IPC task runner.
    const scoped_refptr<base::SingleThreadTaskRunner> ipc_task_runner_;

    const scoped_refptr<base::SingleThreadTaskRunner> main_task_runner_;

    CameraHalAdapter* camera_hal_adapter_;

    // The CameraHalServer implementation receiver.  All the function calls to
    // |receiver_| runs on |ipc_task_runner_|.
    mojo::Receiver<mojom::CameraHalServer> receiver_;

    mojo::Remote<mojom::CameraHalServerCallbacks> callbacks_;

    base::WeakPtrFactory<IPCBridge> weak_ptr_factory_{this};
  };

  // Loads all the camera HAL implementations.  Returns 0 on success;
  // corresponding error code on failure.
  int LoadCameraHal();

  void ExitOnMainThread(int error);

  void OnCameraActivityChange(base::WeakPtr<IPCBridge> ipc_bridge,
                              int32_t camera_id,
                              bool opened,
                              mojom::CameraClientType type);

  std::unique_ptr<CameraMojoChannelManager> mojo_manager_;

  // The instance which deals with the IPC-related calls. It should always run
  // and be deleted on IPC thread.
  std::unique_ptr<IPCBridge> ipc_bridge_;

  // Interfaces of Camera HALs.
  std::vector<cros_camera_hal_t*> cros_camera_hals_;

  // The camera HAL adapter instance.  Each call to CreateChannel creates a
  // new Mojo binding in the camera HAL adapter.  Currently the camera HAL
  // adapter serves two clients: Chrome VideoCaptureDeviceFactory and Android
  // cameraserver process.
  std::unique_ptr<CameraHalAdapter> camera_hal_adapter_;

  THREAD_CHECKER(thread_checker_);
};

}  // namespace cros

#endif  // CAMERA_HAL_ADAPTER_CAMERA_HAL_SERVER_IMPL_H_
