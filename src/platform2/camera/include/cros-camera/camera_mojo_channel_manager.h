/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CAMERA_MOJO_CHANNEL_MANAGER_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CAMERA_MOJO_CHANNEL_MANAGER_H_

#include <memory>
#include <string>

#include <base/functional/callback.h>
#include <base/functional/callback_forward.h>
#include <base/memory/ref_counted.h>
#include <iioservice/mojo/cros_sensor_service.mojom.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/algorithm/camera_algorithm.mojom.h"
#include "camera/mojo/cros_camera_service.mojom.h"
#include "camera/mojo/gpu/jpeg_encode_accelerator.mojom.h"
#include "camera/mojo/gpu/mjpeg_decode_accelerator.mojom.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/sensor_hal_client.h"

namespace base {
class SingleThreadTaskRunner;
}

namespace cros {

// There are many places that need to initialize Mojo and use related channels.
// This class is used to manage them together.
class CROS_CAMERA_EXPORT CameraMojoChannelManager
    : public CameraMojoChannelManagerToken {
 public:
  using Callback = base::OnceCallback<void(void)>;

  virtual ~CameraMojoChannelManager() {}

  // TODO(b/151270948): Remove this method once all camera HALs implement
  // the CrOS specific interface so that we can pass the mojo manager instance
  // to them.
  static CameraMojoChannelManager* GetInstance();

  static CameraMojoChannelManager* FromToken(
      CameraMojoChannelManagerToken* token) {
    return static_cast<CameraMojoChannelManager*>(token);
  }

  // Gets the task runner that the CameraHalDispatcher interface is bound to.
  virtual scoped_refptr<base::SingleThreadTaskRunner> GetIpcTaskRunner() = 0;

  // Registers the camera HAL server pointer |hal_ptr| to the
  // CameraHalDispatcher.
  // This method is expected to be called on the IPC thread and the
  // |on_construct_callback| and |on_error_callback| will be run on the IPC
  // thread as well.
  virtual void RegisterServer(
      mojo::PendingRemote<mojom::CameraHalServer> server,
      mojom::CameraHalDispatcher::RegisterServerWithTokenCallback
          on_construct_callback,
      Callback on_error_callback) = 0;

  // Creates a new MjpegDecodeAccelerator connection by |receiver|.
  // This method is expected to be called on the IPC thread and the
  // |on_construct_callback| and |on_error_callback| will be run on the IPC
  // thread as well.
  virtual void CreateMjpegDecodeAccelerator(
      mojo::PendingReceiver<mojom::MjpegDecodeAccelerator> receiver,
      Callback on_construct_callback,
      Callback on_error_callback) = 0;

  // Creates a new JpegEncodeAccelerator connection by |receiver|.
  // This method is expected to be called on the IPC thread and the
  // |on_construct_callback| and |on_error_callback| will be run on the IPC
  // thread as well.
  virtual void CreateJpegEncodeAccelerator(
      mojo::PendingReceiver<mojom::JpegEncodeAccelerator> receiver,
      Callback on_construct_callback,
      Callback on_error_callback) = 0;

  // Create a new CameraAlgorithmOps remote.
  virtual mojo::Remote<mojom::CameraAlgorithmOps>
  CreateCameraAlgorithmOpsRemote(const std::string& socket_path,
                                 const std::string& pipe_name) = 0;

  virtual SensorHalClient* GetSensorHalClient() = 0;
  virtual void RegisterSensorHalClient(
      mojo::PendingRemote<mojom::SensorHalClient> client,
      mojom::CameraHalDispatcher::RegisterSensorClientWithTokenCallback
          on_construct_callback,
      Callback on_error_callback) = 0;

  virtual void BindServiceToMojoServiceManager(
      const std::string& service_name,
      mojo::ScopedMessagePipeHandle remote) = 0;
};

}  // namespace cros

#endif  // CAMERA_INCLUDE_CROS_CAMERA_CAMERA_MOJO_CHANNEL_MANAGER_H_
