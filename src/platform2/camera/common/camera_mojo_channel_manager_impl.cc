/*
 * Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/camera_mojo_channel_manager_impl.h"

#include <grp.h>

#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/no_destructor.h>
#include <mojo/core/embedder/embedder.h>

#include "cros-camera/common.h"
#include "cros-camera/constants.h"
#include "cros-camera/ipc_util.h"

namespace cros {

namespace {

constexpr char kServerTokenPath[] = "/run/camera_tokens/server/token";
constexpr char kServerSensorClientTokenPath[] =
    "/run/camera_tokens/server/sensor_client_token";

constexpr ino_t kInvalidInodeNum = 0;

// Gets the socket file by |socket_path| and checks if it is in correct group
// and has correct permission. Returns |kInvalidInodeNum| if it is invalid.
// Otherwise, returns its inode number.
ino_t GetSocketInodeNumber(const base::FilePath& socket_path) {
  // Ensure that socket file is ready before trying to connect the dispatcher.
  struct group arc_camera_group;
  struct group* result = nullptr;
  char buf[1024];

  getgrnam_r(constants::kArcCameraGroup, &arc_camera_group, buf, sizeof(buf),
             &result);
  if (!result) {
    return kInvalidInodeNum;
  }

  int mode;
  if (!base::GetPosixFilePermissions(socket_path, &mode) || mode != 0660) {
    return kInvalidInodeNum;
  }

  struct stat st;
  if (stat(socket_path.value().c_str(), &st) ||
      st.st_gid != arc_camera_group.gr_gid) {
    return kInvalidInodeNum;
  }
  return st.st_ino;
}

std::optional<base::UnguessableToken> ReadToken(std::string path) {
  base::FilePath token_path(path);
  std::string token_string;
  if (!base::ReadFileToString(token_path, &token_string)) {
    LOGF(ERROR) << "Failed to read server token";
    return std::nullopt;
  }
  return cros::TokenFromString(token_string);
}

}  // namespace

// static
CameraMojoChannelManagerImpl* CameraMojoChannelManagerImpl::instance_ = nullptr;

CameraMojoChannelManagerImpl::CameraMojoChannelManagerImpl()
    : ipc_thread_("MojoIpcThread"), bound_socket_inode_num_(kInvalidInodeNum) {
  instance_ = this;
  if (!ipc_thread_.StartWithOptions(
          base::Thread::Options(base::MessagePumpType::IO, 0))) {
    LOGF(ERROR) << "Failed to start IPC Thread";
    return;
  }
  mojo::core::Init();
  ipc_support_ = std::make_unique<mojo::core::ScopedIPCSupport>(
      ipc_thread_.task_runner(),
      mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST);

  base::FilePath socket_path(constants::kCrosCameraSocketPathString);
  if (!watcher_.Watch(
          socket_path, base::FilePathWatcher::Type::kNonRecursive,
          base::BindRepeating(
              &CameraMojoChannelManagerImpl::OnSocketFileStatusChange,
              base::Unretained(this)))) {
    LOGF(ERROR) << "Failed to watch socket path";
    return;
  }
}

CameraMojoChannelManagerImpl::~CameraMojoChannelManagerImpl() {
  if (ipc_thread_.IsRunning()) {
    base::AutoLock lock(sensor_lock_);
    sensor_hal_client_.reset();
    ipc_thread_.task_runner()->PostTask(
        FROM_HERE,
        base::BindOnce(
            &CameraMojoChannelManagerImpl::TearDownMojoEnvOnIpcThread,
            base::Unretained(this)));
    ipc_thread_.Stop();
  }
}

// static
CameraMojoChannelManagerToken* CameraMojoChannelManagerToken::CreateInstance() {
  return new CameraMojoChannelManagerImpl();
}

// static
CameraMojoChannelManager* CameraMojoChannelManager::GetInstance() {
  DCHECK(CameraMojoChannelManagerImpl::instance_ != nullptr);
  return CameraMojoChannelManagerImpl::instance_;
}

scoped_refptr<base::SingleThreadTaskRunner>
CameraMojoChannelManagerImpl::GetIpcTaskRunner() {
  CHECK(ipc_thread_.task_runner());
  return ipc_thread_.task_runner();
}

void CameraMojoChannelManagerImpl::RegisterServer(
    mojo::PendingRemote<mojom::CameraHalServer> server,
    mojom::CameraHalDispatcher::RegisterServerWithTokenCallback
        on_construct_callback,
    Callback on_error_callback) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  camera_hal_server_task_ = {
      .pendingReceiverOrRemote = std::move(server),
      .on_construct_callback = std::move(on_construct_callback),
      .on_error_callback = std::move(on_error_callback)};
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraMojoChannelManagerImpl::TryConnectToDispatcher,
                     base::Unretained(this)));
}

void CameraMojoChannelManagerImpl::CreateMjpegDecodeAccelerator(
    mojo::PendingReceiver<mojom::MjpegDecodeAccelerator> receiver,
    Callback on_construct_callback,
    Callback on_error_callback) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  JpegPendingMojoTask<mojo::PendingReceiver<mojom::MjpegDecodeAccelerator>>
      pending_task = {.pendingReceiverOrRemote = std::move(receiver),
                      .on_construct_callback = std::move(on_construct_callback),
                      .on_error_callback = std::move(on_error_callback)};
  jda_tasks_.push_back(std::move(pending_task));
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraMojoChannelManagerImpl::TryConnectToDispatcher,
                     base::Unretained(this)));
}

void CameraMojoChannelManagerImpl::CreateJpegEncodeAccelerator(
    mojo::PendingReceiver<mojom::JpegEncodeAccelerator> receiver,
    Callback on_construct_callback,
    Callback on_error_callback) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  JpegPendingMojoTask<mojo::PendingReceiver<mojom::JpegEncodeAccelerator>>
      pending_task = {.pendingReceiverOrRemote = std::move(receiver),
                      .on_construct_callback = std::move(on_construct_callback),
                      .on_error_callback = std::move(on_error_callback)};
  jea_tasks_.push_back(std::move(pending_task));
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraMojoChannelManagerImpl::TryConnectToDispatcher,
                     base::Unretained(this)));
}

mojo::Remote<mojom::CameraAlgorithmOps>
CameraMojoChannelManagerImpl::CreateCameraAlgorithmOpsRemote(
    const std::string& socket_path, const std::string& pipe_name) {
  mojo::ScopedMessagePipeHandle parent_pipe;
  mojo::Remote<mojom::CameraAlgorithmOps> algorithm_ops;

  base::FilePath socket_file_path(socket_path);
  MojoResult result = cros::CreateMojoChannelToChildByUnixDomainSocket(
      socket_file_path, &parent_pipe, pipe_name);
  if (result != MOJO_RESULT_OK) {
    LOGF(WARNING) << "Failed to create Mojo Channel to "
                  << socket_file_path.value();
    return mojo::Remote<mojom::CameraAlgorithmOps>();
  }

  algorithm_ops.Bind(mojo::PendingRemote<mojom::CameraAlgorithmOps>(
      std::move(parent_pipe), 0u));

  LOGF(INFO) << "Connected to CameraAlgorithmOps";

  return algorithm_ops;
}

SensorHalClient* CameraMojoChannelManagerImpl::GetSensorHalClient() {
  base::AutoLock lock(sensor_lock_);
  if (!sensor_hal_client_) {
    sensor_hal_client_ = std::make_unique<SensorHalClientImpl>(this);
  }
  return sensor_hal_client_.get();
}

void CameraMojoChannelManagerImpl::RegisterSensorHalClient(
    mojo::PendingRemote<mojom::SensorHalClient> client,
    mojom::CameraHalDispatcher::RegisterSensorClientWithTokenCallback
        on_construct_callback,
    Callback on_error_callback) {
  sensor_hal_client_task_ = {
      .pendingReceiverOrRemote = std::move(client),
      .on_construct_callback = std::move(on_construct_callback),
      .on_error_callback = std::move(on_error_callback)};
  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraMojoChannelManagerImpl::TryConnectToDispatcher,
                     base::Unretained(this)));
}

void CameraMojoChannelManagerImpl::BindServiceToMojoServiceManager(
    const std::string& service_name, mojo::ScopedMessagePipeHandle receiver) {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());
  if (!dispatcher_.is_bound()) {
    LOGF(ERROR) << "Dispatcher is not bound!";
    return;
  }
  dispatcher_->BindServiceToMojoServiceManager(service_name,
                                               std::move(receiver));
}

void CameraMojoChannelManagerImpl::OnSocketFileStatusChange(
    const base::FilePath& socket_path, bool error) {
  if (error) {
    LOGF(ERROR) << "Error occurs in socket file watcher.";
    return;
  }

  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &CameraMojoChannelManagerImpl::OnSocketFileStatusChangeOnIpcThread,
          base::Unretained(this)));
}

void CameraMojoChannelManagerImpl::OnSocketFileStatusChangeOnIpcThread() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  base::FilePath socket_path(constants::kCrosCameraSocketPathString);
  if (dispatcher_.is_bound()) {
    // If the dispatcher is already bound but the inode number of the socket is
    // unreadable or has been changed, we assume the other side of the
    // dispatcher (Chrome) might be destroyed. As a result, we fire the on error
    // event here in case it is not fired correctly.
    if (bound_socket_inode_num_ != GetSocketInodeNumber(socket_path)) {
      ipc_thread_.task_runner()->PostTask(
          FROM_HERE,
          base::BindOnce(&CameraMojoChannelManagerImpl::ResetDispatcherPtr,
                         base::Unretained(this)));
    }
    return;
  }

  ipc_thread_.task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&CameraMojoChannelManagerImpl::TryConnectToDispatcher,
                     base::Unretained(this)));
}

void CameraMojoChannelManagerImpl::TryConnectToDispatcher() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  if (dispatcher_.is_bound()) {
    TryConsumePendingMojoTasks();
    return;
  }

  base::FilePath socket_path(constants::kCrosCameraSocketPathString);
  ino_t socket_inode_num = GetSocketInodeNumber(socket_path);
  if (socket_inode_num == kInvalidInodeNum) {
    return;
  }

  mojo::ScopedMessagePipeHandle child_pipe;
  MojoResult result = cros::CreateMojoChannelToParentByUnixDomainSocket(
      socket_path, &child_pipe);
  if (result != MOJO_RESULT_OK) {
    LOGF(WARNING) << "Failed to create Mojo Channel to " << socket_path.value();
    return;
  }

  dispatcher_ = mojo::Remote<cros::mojom::CameraHalDispatcher>(
      mojo::PendingRemote<cros::mojom::CameraHalDispatcher>(
          std::move(child_pipe), 0u));
  dispatcher_.set_disconnect_handler(
      base::BindOnce(&CameraMojoChannelManagerImpl::ResetDispatcherPtr,
                     base::Unretained(this)));
  bound_socket_inode_num_ = socket_inode_num;

  TryConsumePendingMojoTasks();
}

void CameraMojoChannelManagerImpl::TryConsumePendingMojoTasks() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  if (camera_hal_server_task_.pendingReceiverOrRemote) {
    auto server_token = ReadToken(kServerTokenPath);
    if (!server_token.has_value()) {
      LOGF(ERROR) << "Failed to read server token";
      std::move(camera_hal_server_task_.on_construct_callback)
          .Run(-EPERM, mojo::NullRemote());
    } else {
      auto token = mojo_base::mojom::UnguessableToken::New();
      token->high = server_token->GetHighForSerialization();
      token->low = server_token->GetLowForSerialization();
      dispatcher_->RegisterServerWithToken(
          std::move(camera_hal_server_task_.pendingReceiverOrRemote),
          std::move(token),
          std::move(camera_hal_server_task_.on_construct_callback));
    }
  }

  if (sensor_hal_client_task_.pendingReceiverOrRemote) {
    auto server_sensor_client_token = ReadToken(kServerSensorClientTokenPath);
    if (!server_sensor_client_token.has_value()) {
      LOGF(ERROR) << "Failed to read server token for sensor";
      std::move(sensor_hal_client_task_.on_construct_callback).Run(-EPERM);
    } else {
      auto token = mojo_base::mojom::UnguessableToken::New();
      token->high = server_sensor_client_token->GetHighForSerialization();
      token->low = server_sensor_client_token->GetLowForSerialization();
      dispatcher_->RegisterSensorClientWithToken(
          std::move(sensor_hal_client_task_.pendingReceiverOrRemote),
          std::move(token),
          std::move(sensor_hal_client_task_.on_construct_callback));
    }
  }

  for (auto& task : jda_tasks_) {
    if (task.pendingReceiverOrRemote) {
      dispatcher_->GetMjpegDecodeAccelerator(
          std::move(task.pendingReceiverOrRemote));
      std::move(task.on_construct_callback).Run();
    }
  }

  for (auto& task : jea_tasks_) {
    if (task.pendingReceiverOrRemote) {
      dispatcher_->GetJpegEncodeAccelerator(
          std::move(task.pendingReceiverOrRemote));
      std::move(task.on_construct_callback).Run();
    }
  }
}

void CameraMojoChannelManagerImpl::TearDownMojoEnvOnIpcThread() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  ResetDispatcherPtr();
  ipc_support_.reset();
}

void CameraMojoChannelManagerImpl::ResetDispatcherPtr() {
  DCHECK(ipc_thread_.task_runner()->BelongsToCurrentThread());

  if (camera_hal_server_task_.on_error_callback) {
    std::move(camera_hal_server_task_.on_error_callback).Run();
    camera_hal_server_task_ = {};
  }

  if (sensor_hal_client_task_.on_error_callback) {
    std::move(sensor_hal_client_task_.on_error_callback).Run();
    sensor_hal_client_task_ = {};
  }

  for (auto& task : jda_tasks_) {
    if (task.on_error_callback) {
      std::move(task.on_error_callback).Run();
    }
  }
  jda_tasks_.clear();

  for (auto& task : jea_tasks_) {
    if (task.on_error_callback) {
      std::move(task.on_error_callback).Run();
    }
  }
  jea_tasks_.clear();

  dispatcher_.reset();
  bound_socket_inode_num_ = kInvalidInodeNum;
}

}  // namespace cros
