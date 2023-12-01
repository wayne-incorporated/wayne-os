/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/libcamera_connector/camera_service_connector_impl.h"

#include <errno.h>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/no_destructor.h>
#include <base/sequence_checker.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "camera/mojo/unguessable_token.mojom.h"
#include "common/libcamera_connector/types.h"
#include "cros-camera/common.h"
#include "cros-camera/constants.h"
#include "cros-camera/future.h"
#include "cros-camera/ipc_util.h"

namespace cros {

CameraServiceConnector::CameraServiceConnector()
    : ipc_thread_("CamConn"), camera_client_(nullptr) {}

CameraServiceConnector* CameraServiceConnector::GetInstance() {
  static base::NoDestructor<CameraServiceConnector> instance;
  return instance.get();
}

int CameraServiceConnector::Init(const cros_cam_init_option_t* option) {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (initialized_.IsSet()) {
    LOGF(ERROR) << "Should not run init() more than once";
    return -EPERM;
  }

  // TODO(b/170075468): Remove support for api_version 0 when Parallels migrates
  // to api_version 1.
  if (option->api_version >= 1) {
    auto token = TokenFromString(option->token);
    if (!token.has_value()) {
      LOGF(ERROR) << "Failed to parse token string";
      return -EPERM;
    }
    token_ = *token;
  }

  mojo::core::Init();
  bool ret = ipc_thread_.StartWithOptions(
      base::Thread::Options(base::MessagePumpType::IO, 0));
  if (!ret) {
    LOGF(ERROR) << "Failed to start IPC thread";
    return -ENODEV;
  }
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      ipc_thread_.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::CLEAN);

  auto future = cros::Future<int>::Create(nullptr);
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraServiceConnector::InitOnThread,
                     base::Unretained(this), GetFutureCallback(future)));
  int result = future->Get();
  if (result == 0) {
    initialized_.Set();
  }
  return result;
}

int CameraServiceConnector::Exit() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(sequence_checker_);

  if (!initialized_.IsSet()) {
    LOGF(ERROR) << "Should run init() before other functions";
    return -EPERM;
  }

  int ret = camera_client_->Exit();

  ipc_support_ = nullptr;
  ipc_thread_.Stop();

  return ret;
}

int CameraServiceConnector::GetCameraInfo(cros_cam_get_cam_info_cb_t callback,
                                          void* context) {
  if (!initialized_.IsSet()) {
    LOGF(ERROR) << "Should run init() before other functions";
    return -EPERM;
  }

  return camera_client_->SetCameraInfoCallback(callback, context);
}

int CameraServiceConnector::StartCapture(
    const cros_cam_capture_request_t* request,
    cros_cam_capture_cb_t callback,
    void* context) {
  if (!initialized_.IsSet()) {
    LOGF(ERROR) << "Should run init() before other functions";
    return -EPERM;
  }

  LOGF(INFO) << "StartCapture";
  return camera_client_->StartCapture(request, callback, context);
}

int CameraServiceConnector::StopCapture(int id) {
  if (!initialized_.IsSet()) {
    LOGF(ERROR) << "Should run init() before other functions";
    return -EPERM;
  }

  return camera_client_->StopCapture(id);
}

void CameraServiceConnector::RegisterClient(
    mojo::PendingRemote<mojom::CameraHalClient> camera_hal_client,
    IntOnceCallback on_registered_callback) {
  // This may be called from a different thread than the main thread,
  // (for example here it is called from CameraClient thread),
  // but mojo operations have to run on the same thread that bound
  // the interface, so we bounce the request over to that thread/runner.
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraServiceConnector::RegisterClientOnThread,
                     base::Unretained(this), std::move(camera_hal_client),
                     std::move(on_registered_callback)));
}

void CameraServiceConnector::RegisterClientOnThread(
    mojo::PendingRemote<mojom::CameraHalClient> camera_hal_client,
    IntOnceCallback on_registered_callback) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  DCHECK(!token_.is_empty());

  auto mojo_token = mojo_base::mojom::UnguessableToken::New();
  mojo_token->high = token_.GetHighForSerialization();
  mojo_token->low = token_.GetLowForSerialization();
  dispatcher_->RegisterClientWithToken(
      std::move(camera_hal_client), cros::mojom::CameraClientType::UNKNOWN,
      std::move(mojo_token),
      base::BindOnce(&CameraServiceConnector::OnRegisteredClient,
                     base::Unretained(this),
                     std::move(on_registered_callback)));
}

void CameraServiceConnector::OnRegisteredClient(
    IntOnceCallback on_registered_callback, int32_t result) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  if (result != 0) {
    LOGF(ERROR) << "Failed to register client: " << result;
  }
  std::move(on_registered_callback).Run(result);
}

void CameraServiceConnector::InitOnThread(IntOnceCallback init_callback) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  mojo::ScopedMessagePipeHandle child_pipe;
  base::FilePath socket_path(constants::kCrosCameraSocketPathString);
  MojoResult res =
      CreateMojoChannelToParentByUnixDomainSocket(socket_path, &child_pipe);
  if (res != MOJO_RESULT_OK) {
    LOGF(ERROR) << "Failed to create mojo channel to dispatcher";
    std::move(init_callback).Run(-ENODEV);
    return;
  }

  dispatcher_ = mojo::Remote<mojom::CameraHalDispatcher>(
      mojo::PendingRemote<mojom::CameraHalDispatcher>(std::move(child_pipe),
                                                      0u));
  bool connected = dispatcher_.is_bound();
  if (!connected) {
    LOGF(ERROR) << "Failed to make a proxy to dispatcher";
    std::move(init_callback).Run(-ENODEV);
    return;
  }
  dispatcher_.set_disconnect_handler(base::BindOnce(
      &CameraServiceConnector::OnDispatcherError, base::Unretained(this)));
  LOGF(INFO) << "Dispatcher connected";

  camera_client_ = std::make_unique<CameraClient>();
  camera_client_->Init(base::BindOnce(&CameraServiceConnector::RegisterClient,
                                      base::Unretained(this)),
                       std::move(init_callback));
}

void CameraServiceConnector::OnDispatcherError() {
  // TODO(b/151047930): Attempt to reconnect on dispatcher error.
  LOGF(FATAL) << "Connection to camera dispatcher lost";
  dispatcher_.reset();
}

}  // namespace cros
