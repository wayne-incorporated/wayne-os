// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mojo_service_manager/daemon/daemon.h"

#include <linux/limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sysexits.h>

#include <memory>
#include <string>
#include <utility>

#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/task/single_thread_task_runner.h>
#include <chromeos/constants/mojo_service_manager.h>
#include <mojo/public/cpp/platform/platform_channel_endpoint.h>
#include <mojo/public/cpp/system/invitation.h>

#include "mojo_service_manager/daemon/service_manager.h"
#include "mojo_service_manager/daemon/service_policy_loader.h"

namespace chromeos {
namespace mojo_service_manager {
namespace {

// Allow others to write so others can connect to the socket. The ACLs are
// controlled by the policy files so we don't need to do it again by the system
// user / group.
constexpr mode_t kSocketMode =
    S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

base::ScopedFD CreateUnixDomainSocket(const base::FilePath& socket_path) {
  base::ScopedFD socket_fd{
      socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0)};
  if (!socket_fd.is_valid()) {
    PLOG(ERROR) << "Failed to create socket.";
    return base::ScopedFD{};
  }

  struct sockaddr_un unix_addr {
    .sun_family = AF_UNIX,
  };
  constexpr size_t kMaxSize =
      sizeof(unix_addr.sun_path) - /*NULL-terminator*/ 1;
  CHECK_LE(socket_path.value().size(), kMaxSize);
  strncpy(unix_addr.sun_path, socket_path.value().c_str(), kMaxSize);

  if (bind(socket_fd.get(), reinterpret_cast<const sockaddr*>(&unix_addr),
           sizeof(unix_addr)) < 0) {
    PLOG(ERROR) << "Failed to bind: " << socket_path.value();
    return base::ScopedFD{};
  }

  if (!base::SetPosixFilePermissions(socket_path, kSocketMode)) {
    PLOG(ERROR) << "Failed to chmod the socket: " << socket_path.value();
    return base::ScopedFD{};
  }

  if (listen(socket_fd.get(), SOMAXCONN) < 0) {
    PLOG(ERROR) << "Failed to listen " << socket_path.value();
    return base::ScopedFD{};
  }

  return socket_fd;
}

base::ScopedFD AcceptSocket(const base::ScopedFD& server_fd) {
  return base::ScopedFD{HANDLE_EINTR(accept4(server_fd.get(), nullptr, nullptr,
                                             SOCK_NONBLOCK | SOCK_CLOEXEC))};
}

mojo::PendingReceiver<mojom::ServiceManager> SendMojoInvitationAndPassReceiver(
    base::ScopedFD peer) {
  mojo::OutgoingInvitation invitation;
  mojo::PendingReceiver<mojom::ServiceManager> receiver{
      invitation.AttachMessagePipe(kMojoInvitationPipeName)};
  mojo::OutgoingInvitation::Send(
      std::move(invitation), base::kNullProcessHandle,
      mojo::PlatformChannelEndpoint(mojo::PlatformHandle(std::move(peer))));
  return receiver;
}

}  // namespace

std::string GetSEContextStringFromChar(const char* buf, size_t len) {
  // The length may or may not contains the null-terminator.
  if (len > 0 && buf[len - 1] == '\0') {
    return std::string(buf);
  }
  return std::string(buf, len);
}

Daemon::Delegate::Delegate() = default;

Daemon::Delegate::~Delegate() = default;

int Daemon::Delegate::GetSockOpt(const base::ScopedFD& socket,
                                 int level,
                                 int optname,
                                 void* optval,
                                 socklen_t* optlen) const {
  return getsockopt(socket.get(), level, optname, optval, optlen);
}

ServicePolicyMap Daemon::Delegate::LoadPolicyFiles(
    const std::vector<base::FilePath>& policy_dir_paths) const {
  ServicePolicyMap res;
  LoadAllServicePolicyFileFromDirectories(policy_dir_paths, &res);
  return res;
}

Daemon::Daemon(Delegate* delegate,
               const base::FilePath& socket_path,
               const std::vector<base::FilePath>& policy_dir_paths,
               Configuration configuration)
    : ipc_support_(std::make_unique<mojo::core::ScopedIPCSupport>(
          base::SingleThreadTaskRunner::GetCurrentDefault(),
          // Don't block shutdown. All mojo pipes are not expected to work after
          // the broker shutdown, so we don't need to wait them.
          mojo::core::ScopedIPCSupport::ShutdownPolicy::FAST)),
      delegate_(delegate),
      socket_path_(socket_path),
      policy_dir_paths_(std::move(policy_dir_paths)),
      configuration_(std::move(configuration)) {}

Daemon::~Daemon() {}

int Daemon::OnInit() {
  int ret = brillo::Daemon::OnInit();
  if (ret != EX_OK)
    return ret;

  // Creates the socket as early as possible to reduce the time of clients that
  // poll and wait for the socket file to be created.
  socket_fd_ = CreateUnixDomainSocket(socket_path_);
  if (!socket_fd_.is_valid()) {
    LOG(ERROR) << "Failed to create socket server at path: " << socket_path_;
    return EX_OSERR;
  }

  service_manager_ = std::make_unique<ServiceManager>(
      std::move(configuration_), delegate_->LoadPolicyFiles(policy_dir_paths_));

  socket_watcher_ = base::FileDescriptorWatcher::WatchReadable(
      socket_fd_.get(),
      base::BindRepeating(&Daemon::SendMojoInvitationAndBindReceiver,
                          base::Unretained(this)));

  LOG(INFO) << "mojo_service_manager started.";
  return EX_OK;
}

void Daemon::OnShutdown(int* exit_code) {
  LOG(INFO) << "mojo_service_manager is shutdowning with exit code: "
            << *exit_code;

  // Manually reset these objects to prevent them posting tasks to the message
  // loop during shutdowning.
  socket_watcher_.reset();
  service_manager_.reset();
  socket_fd_.reset();
  // This need to be reset manually to trigger the shutdown of mojo. Otherwise,
  // the mojo broker tasks could block the message queue during shutdowning.
  ipc_support_.reset();
}

void Daemon::SendMojoInvitationAndBindReceiver() {
  base::ScopedFD peer = AcceptSocket(socket_fd_);
  if (!peer.is_valid()) {
    LOG(ERROR) << "Failed to accept peer socket";
    return;
  }
  mojom::ProcessIdentityPtr identity = GetProcessIdentityFromPeerSocket(peer);
  mojo::PendingReceiver<mojom::ServiceManager> receiver =
      SendMojoInvitationAndPassReceiver(std::move(peer));
  if (!identity) {
    receiver.ResetWithReason(
        static_cast<uint32_t>(mojom::ErrorCode::kUnexpectedOsError),
        "Cannot get identity from peer socket.");
    return;
  }
  // TODO(b/234569073): Remove this log after we fully enable service manager.
  LOG(INFO) << "Receive connection from: " << identity->security_context;
  DCHECK(service_manager_);
  service_manager_->AddReceiver(std::move(identity), std::move(receiver));
}

mojom::ProcessIdentityPtr Daemon::GetProcessIdentityFromPeerSocket(
    const base::ScopedFD& peer) const {
  auto identity = mojom::ProcessIdentity::New();
  struct ucred ucred_data {};
  socklen_t len = sizeof(ucred_data);
  if (delegate_->GetSockOpt(peer, SOL_SOCKET, SO_PEERCRED, &ucred_data, &len) <
      0) {
    PLOG(ERROR) << "Failed to get SO_PEERCRED from peer socket.";
    return nullptr;
  }
  static_assert(sizeof(ucred_data.pid) == 4);
  static_assert(sizeof(ucred_data.uid) == 4);
  static_assert(sizeof(ucred_data.gid) == 4);
  identity->pid = static_cast<uint32_t>(ucred_data.pid);
  identity->uid = static_cast<uint32_t>(ucred_data.uid);
  identity->gid = static_cast<uint32_t>(ucred_data.gid);

  char buf[NAME_MAX] = {};
  len = NAME_MAX;
  if (delegate_->GetSockOpt(peer, SOL_SOCKET, SO_PEERSEC, &buf, &len) < 0) {
    PLOG(ERROR) << "Failed to get SO_PEERSEC from peer socket.";
    return nullptr;
  }
  identity->security_context = GetSEContextStringFromChar(buf, len);
  if (identity->security_context.size() == 0) {
    LOG(ERROR) << "The length of security context gotten from socket is 0.";
    return nullptr;
  }
  return identity;
}

}  // namespace mojo_service_manager
}  // namespace chromeos
