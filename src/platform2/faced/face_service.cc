// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/face_service.h"

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>

#include "base/check.h"
#include "faced/util/status.h"
#include "faced/util/task.h"

namespace faced {

namespace {

// This socket number represents the socket that the FaceService app will
// communicate to the parent (faced) with via gRPC.
//
// This socket number needs to be consistent with the socket number that is set
// in the FaceService code of the binary that runs within the minijail
// environment.
inline constexpr int kChildSocket = 3;

// Path of the FaceService application
constexpr base::StringPiece kFaceServiceApplicationPath =
    "/opt/google/faceauth/face_service";

}  // namespace

absl::StatusOr<std::pair<base::ScopedFD, base::ScopedFD>> SocketPair() {
  int fds[2];
  int result = socketpair(AF_UNIX, SOCK_STREAM, /*protocol=*/0, fds);
  if (result < 0) {
    return absl::InternalError("Could not create socket pair");
  }
  return {std::make_pair(base::ScopedFD(fds[0]), base::ScopedFD(fds[1]))};
}

// FaceServiceProcess method definitions below

absl::StatusOr<std::unique_ptr<FaceServiceProcess>>
FaceServiceProcess::Create() {
  std::unique_ptr<FaceServiceProcess> process =
      std::make_unique<FaceServiceProcess>();

  absl::Status started_status = process->Start();
  if (!started_status.ok()) {
    return started_status;
  }

  return process;
}

absl::Status FaceServiceProcess::Start() {
  // Start a minijail process containing the FaceService application
  jail_ = ScopedMinijail(minijail_new());

  // Prevent Linux capabilities our process has from being inherited by our
  // child.
  minijail_use_caps(jail_.get(), /*capmask=*/0);

  minijail_namespace_vfs(jail_.get());
  minijail_remount_proc_readonly(jail_.get());
  minijail_namespace_pids(jail_.get());
  minijail_namespace_net(jail_.get());

  // Run the child job as user "nobody"
  minijail_change_user(jail_.get(), "nobody");

  // Change the group to "nobody"
  minijail_change_group(jail_.get(), "nobody");

  // Child process should inherit all supplementary groups of "nobody"
  minijail_inherit_usergroups(jail_.get());

  // Create a socket for communication with the child process
  std::pair<base::ScopedFD, base::ScopedFD> sockets;
  FACE_ASSIGN_OR_RETURN(sockets, SocketPair());

  // Give the child process the other side of our socket pair. By
  // convention, this is passed in as FD 1 (stdout).
  minijail_preserve_fd(jail_.get(),
                       /*parent_fd=*/sockets.second.get(), kChildSocket);

  if (VLOG_IS_ON(1)) {
    // Preserve the child process's stdout & stederr FDs.
    minijail_preserve_fd(jail_.get(), STDOUT_FILENO, STDOUT_FILENO);
    minijail_preserve_fd(jail_.get(), STDERR_FILENO, STDERR_FILENO);
    // Write debug from inside the minijail to STDERR.
    minijail_log_to_fd(STDERR_FILENO, 7);  // 7 is "debug" level
  }

  // Close all FDs in the child, other than those we explicitly configure above.
  minijail_close_open_fds(jail_.get());

  // Fork and exec FaceService from the child process
  pid_t pid = -1;
  char* const argv[] = {nullptr};
  int ret = minijail_run_pid_pipes_no_preload(
      jail_.get(), kFaceServiceApplicationPath.data(), argv, &pid, nullptr,
      nullptr, nullptr);
  if (ret != 0) {
    return absl::InternalError("FaceService failed to start.");
  }
  VLOG(1) << "FaceService started (" << pid << ")";

  // Close our FD to the child's socket.
  sockets.second.reset();

  fd_ = std::move(sockets.first);

  return absl::OkStatus();
}

absl::StatusOr<std::unique_ptr<FaceServiceClient>>
FaceServiceProcess::CreateClient() {
  if (!fd_.is_valid()) {
    return absl::AlreadyExistsError("Client has already been created.");
  }
  return std::make_unique<FaceServiceClient>(std::move(fd_));
}

absl::Status FaceServiceProcess::ShutDown() {
  fd_.reset();

  // Kill the process running in minijail.
  int ret = minijail_kill(jail_.get());

  // Process exited with SIGTERM as expected.
  if (ret == MINIJAIL_ERR_SIG_BASE + SIGTERM) {
    return absl::OkStatus();
  }

  if (ret < 0) {
    ret = -ret;
    if (ret == ESRCH) {
      // Process has already been waited for and we consider shutdown a success.
      return absl::OkStatus();
    }
  }

  return absl::UnknownError("Error stopping FaceService");
}

// FaceServiceClient method definitions below

FaceServiceClient::FaceServiceClient(base::ScopedFD fd) {
  // Create the gRPC channel
  channel_ = grpc::CreateInsecureChannelFromFd("", fd.release());

  // Create a gRPC client that will be leased through FaceServiceClient
  rpc_client_ =
      std::make_unique<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>(
          CurrentSequence(), faceauth::eora::FaceService::NewStub(channel_));
}

brillo::AsyncGrpcClient<faceauth::eora::FaceService>*
FaceServiceClient::GetAsyncClient() {
  return rpc_client_.get();
}

void FaceServiceClient::ShutDown() {
  // Pass ownership of `rpc_client_` to the ShutDown callback.
  //
  // We can't delete the client until its async shut down operation
  // has completed. To avoid forcing our own clients to wait, we pass
  // ownership of the client to the closure, which will delete the client
  // when shut down is complete.
  brillo::AsyncGrpcClient<faceauth::eora::FaceService>* client =
      rpc_client_.get();
  client->ShutDown(base::BindOnce(
      [](std::unique_ptr<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>
             client) {
        // Client has been shut down, so it is now safe to clean up.
        client.reset();
      },
      std::move(rpc_client_)));
}

FaceServiceClient::~FaceServiceClient() {
  if (rpc_client_) {
    ShutDown();
  }
}

// FaceServiceManager method definitions below

std::unique_ptr<FaceServiceManager> FaceServiceManager::Create() {
  std::unique_ptr<FaceServiceManager> mgr =
      std::make_unique<FaceServiceManager>();

  absl::StatusOr<std::unique_ptr<FaceServiceProcess>> process =
      FaceServiceProcess::Create();
  if (process.ok()) {
    mgr->process_ = std::move(process.value());
  }

  return mgr;
}

absl::StatusOr<Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>>
FaceServiceManager::LeaseClient() {
  if (leased_) {
    return absl::AlreadyExistsError("Client already in use");
  }

  // Lazily start the process.
  if (!process_) {
    absl::StatusOr<std::unique_ptr<FaceServiceProcess>> process =
        FaceServiceProcess::Create();
    if (!process.ok()) {
      return process.status();
    }
    process_ = std::move(process.value());
  }

  // Lazily create a client.
  if (!client_) {
    absl::StatusOr<std::unique_ptr<FaceServiceClient>> client =
        process_->CreateClient();
    if (!client.ok()) {
      return client.status();
    }
    client_ = std::move(client.value());
  }

  leased_ = true;
  return Lease<brillo::AsyncGrpcClient<faceauth::eora::FaceService>>(
      client_->GetAsyncClient(),
      base::BindOnce(&FaceServiceManager::OnReleaseClient,
                     base::Unretained(this)));
}

void FaceServiceManager::OnReleaseClient() {
  leased_ = false;
}

FaceServiceManager::~FaceServiceManager() {
  CHECK(leased_ == false)
      << "FaceServiceManager instance destroyed while client remains leased.";

  if (process_) {
    (void)process_->ShutDown();
    process_.reset();
  }
}

}  // namespace faced
