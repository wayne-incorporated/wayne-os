// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mojo_service_manager/lib/connect.h"

#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <cstdlib>
#include <utility>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>
#include <chromeos/constants/mojo_service_manager.h>
#include <mojo/public/cpp/bindings/remote.h>
#include <mojo/public/cpp/platform/platform_channel.h>
#include <mojo/public/cpp/system/invitation.h>

namespace chromeos::mojo_service_manager {
namespace {

// The connection may fail if the socket does not exist or the permission is not
// set to the right permission. This could happen if the ChromeOS mojo service
// manager is starting. We may need to wait for a while and retry.
//
// TODO(b/234318452): Clean up this retry logic after we collect enough UMA
// data.
//
// The retry interval of connecting to the service manager. It is expected that
// normally the first retry should be able to perform the bootstrap on all
// devices.
constexpr base::TimeDelta kRetryInterval = base::Milliseconds(1);
// The retry timeout of connecting to the service manager.
constexpr base::TimeDelta kRetryTimeout = base::Seconds(5);

base::ScopedFD ConnectToServiceManagerUnixSocket(
    const base::FilePath& socket_path) {
  base::ScopedFD sock{socket(AF_UNIX, SOCK_STREAM, 0)};
  if (!sock.is_valid()) {
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

  int rc = HANDLE_EINTR(connect(sock.get(),
                                reinterpret_cast<const sockaddr*>(&unix_addr),
                                sizeof(unix_addr)));
  if (rc == -1 && errno != EISCONN) {
    PLOG(ERROR) << "Failed to connect to service manager unix socket";
    return base::ScopedFD{};
  }
  return sock;
}

mojo::PendingRemote<mojom::ServiceManager> AcceptMojoInvitationAndPassRemote(
    base::ScopedFD sock) {
  auto invitation = mojo::IncomingInvitation::Accept(
      mojo::PlatformChannelEndpoint(mojo::PlatformHandle(std::move(sock))));
  mojo::ScopedMessagePipeHandle pipe =
      invitation.ExtractMessagePipe(kMojoInvitationPipeName);
  return mojo::PendingRemote<mojom::ServiceManager>(std::move(pipe), 0u);
}

mojo::PendingRemote<mojom::ServiceManager> ConnectToMojoServiceManagerInteral(
    const base::FilePath& socket_path) {
  for (base::ElapsedTimer timer; timer.Elapsed() < kRetryTimeout;
       base::PlatformThread::Sleep(kRetryInterval)) {
    base::ScopedFD sock = ConnectToServiceManagerUnixSocket(socket_path);
    if (sock.is_valid())
      return AcceptMojoInvitationAndPassRemote(std::move(sock));
  }
  LOG(ERROR) << "Failed to connect to mojo service manager before the timeout "
                "exceeded.";
  return mojo::PendingRemote<mojom::ServiceManager>{};
}

}  // namespace

BRILLO_EXPORT mojo::PendingRemote<mojom::ServiceManager>
ConnectToMojoServiceManager() {
  return ConnectToMojoServiceManagerInteral(base::FilePath{kSocketPath});
}

mojo::PendingRemote<mojom::ServiceManager>
ConnectToMojoServiceManagerForTesting(const base::FilePath& socket_path) {
  return ConnectToMojoServiceManagerInteral(socket_path);
}

}  // namespace chromeos::mojo_service_manager
