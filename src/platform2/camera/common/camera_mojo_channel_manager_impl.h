/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_MOJO_CHANNEL_MANAGER_IMPL_H_
#define CAMERA_COMMON_CAMERA_MOJO_CHANNEL_MANAGER_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path_watcher.h>
#include <base/no_destructor.h>
#include <base/synchronization/lock.h>
#include <base/threading/thread.h>
#include <iioservice/mojo/cros_sensor_service.mojom.h>
#include <mojo/core/embedder/scoped_ipc_support.h>
#include <mojo/public/cpp/bindings/pending_receiver.h>
#include <mojo/public/cpp/bindings/pending_remote.h>
#include <mojo/public/cpp/bindings/remote.h>

#include "camera/mojo/cros_camera_service.mojom.h"
#include "camera/mojo/unguessable_token.mojom.h"
#include "common/sensor_hal_client_impl.h"
#include "cros-camera/camera_mojo_channel_manager.h"
#include "cros-camera/future.h"

namespace cros {

class CameraMojoChannelManagerImpl : public CameraMojoChannelManager {
 public:
  CameraMojoChannelManagerImpl();
  CameraMojoChannelManagerImpl(const CameraMojoChannelManagerImpl&) = delete;
  CameraMojoChannelManagerImpl& operator=(const CameraMojoChannelManagerImpl&) =
      delete;

  ~CameraMojoChannelManagerImpl() override;

  // CameraMojoChannelManager implementations.

  scoped_refptr<base::SingleThreadTaskRunner> GetIpcTaskRunner() override;

  void RegisterServer(
      mojo::PendingRemote<mojom::CameraHalServer> server,
      mojom::CameraHalDispatcher::RegisterServerWithTokenCallback
          on_construct_callback,
      Callback on_error_callback) override;

  void CreateMjpegDecodeAccelerator(
      mojo::PendingReceiver<mojom::MjpegDecodeAccelerator> receiver,
      Callback on_construct_callback,
      Callback on_error_callback) override;

  void CreateJpegEncodeAccelerator(
      mojo::PendingReceiver<mojom::JpegEncodeAccelerator> receiver,
      Callback on_construct_callback,
      Callback on_error_callback) override;

  mojo::Remote<mojom::CameraAlgorithmOps> CreateCameraAlgorithmOpsRemote(
      const std::string& socket_path, const std::string& pipe_name) override;

  SensorHalClient* GetSensorHalClient() override;

  void RegisterSensorHalClient(
      mojo::PendingRemote<mojom::SensorHalClient> client,
      mojom::CameraHalDispatcher::RegisterSensorClientWithTokenCallback
          on_construct_callback,
      Callback on_error_callback) override;

  void BindServiceToMojoServiceManager(
      const std::string& service_name,
      mojo::ScopedMessagePipeHandle receiver) override;

 protected:
  friend class CameraMojoChannelManager;

  // Thread for IPC chores.
  base::Thread ipc_thread_;

 private:
  template <typename T, typename ConstructCallbackType>
  struct PendingMojoTask {
    T pendingReceiverOrRemote;
    ConstructCallbackType on_construct_callback;
    Callback on_error_callback;
  };

  using ServerPendingMojoTask = PendingMojoTask<
      mojo::PendingRemote<mojom::CameraHalServer>,
      mojom::CameraHalDispatcher::RegisterServerWithTokenCallback>;

  using SensorClientPendingMojoTask = PendingMojoTask<
      mojo::PendingRemote<mojom::SensorHalClient>,
      mojom::CameraHalDispatcher::RegisterSensorClientWithTokenCallback>;

  template <typename T>
  using JpegPendingMojoTask = PendingMojoTask<T, Callback>;

  void OnSocketFileStatusChange(const base::FilePath& socket_path, bool error);

  // Callback method for the unix domain socket file change events.  The method
  // will try to establish the Mojo connection to the CameraHalDispatcher
  // started by Chrome.
  void OnSocketFileStatusChangeOnIpcThread();

  void TryConnectToDispatcher();

  void TryConsumePendingMojoTasks();

  void TearDownMojoEnvOnIpcThread();

  // Reset the dispatcher.
  void ResetDispatcherPtr();

  // The Mojo channel to CameraHalDispatcher in Chrome. All the Mojo
  // communication to |dispatcher_| happens on |ipc_thread_|.
  mojo::Remote<mojom::CameraHalDispatcher> dispatcher_;
  std::unique_ptr<mojo::core::ScopedIPCSupport> ipc_support_;

  // Watches for change events on the unix domain socket file created by Chrome.
  // Upon file change OnSocketFileStatusChange will be called to initiate
  // connection to CameraHalDispatcher.
  base::FilePathWatcher watcher_;

  // Inode number of current bound socket file.
  ino_t bound_socket_inode_num_;

  // Pending Mojo tasks information which should be consumed when the
  // |dispatcher_| is connected.
  ServerPendingMojoTask camera_hal_server_task_;
  SensorClientPendingMojoTask sensor_hal_client_task_;
  std::vector<
      JpegPendingMojoTask<mojo::PendingReceiver<mojom::JpegEncodeAccelerator>>>
      jea_tasks_;
  std::vector<
      JpegPendingMojoTask<mojo::PendingReceiver<mojom::MjpegDecodeAccelerator>>>
      jda_tasks_;

  // TODO(b/151270948): Remove this static variable once we implemnet CrOS
  // specific interface on all camera HALs.
  static CameraMojoChannelManagerImpl* instance_;

  // This lock is to protect |sensor_hal_client_|'s accesses from different
  // threads.
  base::Lock sensor_lock_;
  // The SensorHalClient instance that connects to iioservice for sensors data.
  std::unique_ptr<SensorHalClientImpl> sensor_hal_client_
      GUARDED_BY(sensor_lock_);
};

}  // namespace cros
#endif  // CAMERA_COMMON_CAMERA_MOJO_CHANNEL_MANAGER_IMPL_H_
