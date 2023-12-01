// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/server_proxy.h"

#include <linux/sync_file.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/posix/unix_domain_socket.h>
#include <base/stl_util.h>
#include <base/synchronization/waitable_event.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/files/file_util.h>
#include <brillo/userdb_utils.h>

#include "arc/vm/mojo_proxy/file_descriptor_util.h"
#include "arc/vm/mojo_proxy/message.pb.h"
#include "arc/vm/mojo_proxy/mojo_proxy.h"
#include "arc/vm/mojo_proxy/proxy_file_system.h"

namespace arc {
namespace {

// Crosvm connects to this socket when creating a new virtwl context.
constexpr char kVirtwlSocketPath[] = "/run/arcvm/mojo/mojo-proxy.sock";

// Sets up a socket to accept virtwl connections.
base::ScopedFD SetupVirtwlSocket() {
  // Delete the socket created by a previous run if any.
  if (!brillo::DeleteFile(base::FilePath(kVirtwlSocketPath))) {
    PLOG(ERROR) << "DeleteFile() failed " << kVirtwlSocketPath;
    return {};
  }
  // Bind a socket to the path.
  base::ScopedFD sock(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!sock.is_valid()) {
    PLOG(ERROR) << "socket() failed";
    return {};
  }
  struct sockaddr_un unix_addr = {};
  unix_addr.sun_family = AF_UNIX;
  strncpy(unix_addr.sun_path, kVirtwlSocketPath, sizeof(unix_addr.sun_path));
  if (bind(sock.get(), reinterpret_cast<const sockaddr*>(&unix_addr),
           sizeof(unix_addr)) < 0) {
    PLOG(ERROR) << "bind failed " << kVirtwlSocketPath;
    return {};
  }
  // Make it accessible to crosvm.
  if (chmod(kVirtwlSocketPath, 0666) == -1) {
    PLOG(ERROR) << "Failed to set permission";
    return {};
  }
  // Start listening on the socket.
  if (listen(sock.get(), SOMAXCONN) < 0) {
    PLOG(ERROR) << "listen failed";
    return {};
  }
  return sock;
}

}  // namespace

ServerProxy::ServerProxy(
    scoped_refptr<base::TaskRunner> proxy_file_system_task_runner,
    const base::FilePath& proxy_file_system_mount_path,
    base::OnceClosure quit_closure)
    : proxy_file_system_task_runner_(proxy_file_system_task_runner),
      proxy_file_system_(this,
                         base::SingleThreadTaskRunner::GetCurrentDefault(),
                         proxy_file_system_mount_path),
      quit_closure_(std::move(quit_closure)) {}

ServerProxy::~ServerProxy() = default;

bool ServerProxy::Initialize() {
  // Initialize ProxyFileSystem.
  base::WaitableEvent file_system_initialized(
      base::WaitableEvent::ResetPolicy::MANUAL,
      base::WaitableEvent::InitialState::NOT_SIGNALED);
  bool result = false;
  proxy_file_system_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](ProxyFileSystem* proxy_file_system,
             base::WaitableEvent* file_system_initialized, bool* result) {
            *result = proxy_file_system->Init();
            file_system_initialized->Signal();
          },
          &proxy_file_system_, &file_system_initialized, &result));
  file_system_initialized.Wait();
  if (!result) {
    LOG(ERROR) << "Failed to initialize ProxyFileSystem.";
    return false;
  }

  // Start listening on mojo-proxy.sock.
  virtwl_socket_ = SetupVirtwlSocket();
  if (!virtwl_socket_.is_valid()) {
    LOG(ERROR) << "Failed to set up virtwl socket.";
    return false;
  }

  // Accept connection from crosvm.
  // When the guest proxy creates a new virtwl context whose name is "mojo",
  // crosvm handles it by associating the virtwl context with mojo-proxy.sock.
  LOG(INFO) << "Accepting guest virtwl connection...";
  virtwl_context_ = AcceptSocket(virtwl_socket_.get());
  if (!virtwl_context_.is_valid()) {
    LOG(ERROR) << "Failed to accept virtwl connection";
    return false;
  }

  // Use virtwl to receive messages from guest.
  LOG(INFO) << "Using virtwl to receive messages.";
  message_stream_ = std::make_unique<MessageStream>(std::move(virtwl_context_));

  mojo_proxy_ = std::make_unique<MojoProxy>(this);
  LOG(INFO) << "ServerProxy has started to work.";
  return true;
}

base::ScopedFD ServerProxy::CreateProxiedRegularFile(int64_t handle,
                                                     int32_t flags) {
  // Create a file descriptor which is handled by |proxy_file_system_|.
  return proxy_file_system_.RegisterHandle(handle, flags);
}

bool ServerProxy::SendMessage(const arc_proxy::MojoMessage& message,
                              const std::vector<base::ScopedFD>& fds) {
  if (!fds.empty()) {
    for (const auto& fd : fds) {
      // Virtwl only supports sending sync_files from the host to the guest.
      struct sync_file_info info = {};
      if (ioctl(fd.get(), SYNC_IOC_FILE_INFO, &info)) {
        LOG(ERROR) << "Unsupported host FD";
        return false;
      }
    }
  }
  return message_stream_->Write(message, fds);
}

bool ServerProxy::ReceiveMessage(arc_proxy::MojoMessage* message,
                                 std::vector<base::ScopedFD>* fds) {
  return message_stream_->Read(message, fds);
}

void ServerProxy::OnStopped() {
  std::move(quit_closure_).Run();
}

void ServerProxy::Pread(int64_t handle,
                        uint64_t count,
                        uint64_t offset,
                        PreadCallback callback) {
  mojo_proxy_->Pread(handle, count, offset, std::move(callback));
}

void ServerProxy::Pwrite(int64_t handle,
                         std::string blob,
                         uint64_t offset,
                         PwriteCallback callback) {
  mojo_proxy_->Pwrite(handle, std::move(blob), offset, std::move(callback));
}

void ServerProxy::Close(int64_t handle) {
  mojo_proxy_->Close(handle);
}

void ServerProxy::Fstat(int64_t handle, FstatCallback callback) {
  mojo_proxy_->Fstat(handle, std::move(callback));
}

void ServerProxy::Ftruncate(int64_t handle,
                            int64_t length,
                            FtruncateCallback callback) {
  mojo_proxy_->Ftruncate(handle, length, std::move(callback));
}

}  // namespace arc
