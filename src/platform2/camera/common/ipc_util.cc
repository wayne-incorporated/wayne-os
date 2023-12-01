/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/ipc_util.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <vector>

#include <base/check.h>
#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/rand_util.h>
#include <base/strings/string_number_conversions.h>
#include <mojo/public/cpp/platform/platform_channel.h>
#include <mojo/public/cpp/platform/socket_utils_posix.h>
#include <mojo/public/cpp/system/invitation.h>

#include "cros-camera/common.h"

namespace cros {

namespace {

// The following four functions were taken from
// ipc/unix_domain_socket_util.{h,cc}.

static const size_t kMaxSocketNameLength = 104;

bool CreateUnixDomainSocket(base::ScopedFD* out_fd) {
  DCHECK(out_fd);

  // Create the unix domain socket.
  base::ScopedFD fd(socket(AF_UNIX, SOCK_STREAM, 0));
  if (!fd.is_valid()) {
    PLOGF(ERROR) << "Failed to create AF_UNIX socket:";
    return false;
  }

  // Now set it as non-blocking.
  if (!base::SetNonBlocking(fd.get())) {
    PLOGF(ERROR) << "base::SetNonBlocking() on " << fd.get() << " failed:";
    return false;
  }

  if (fd.get() != out_fd->get())
    *out_fd = std::move(fd);

  return true;
}

bool MakeUnixAddrForPath(const std::string& socket_name,
                         struct sockaddr_un* unix_addr,
                         size_t* unix_addr_len) {
  DCHECK(unix_addr);
  DCHECK(unix_addr_len);

  if (socket_name.length() == 0) {
    LOGF(ERROR) << "Empty socket name provided for unix socket address.";
    return false;
  }
  // We reject socket_name.length() == kMaxSocketNameLength to make room for
  // the NUL terminator at the end of the string.
  if (socket_name.length() >= kMaxSocketNameLength) {
    LOGF(ERROR) << "Socket name too long: " << socket_name;
    return false;
  }

  // Create unix_addr structure.
  memset(unix_addr, 0, sizeof(struct sockaddr_un));
  unix_addr->sun_family = AF_UNIX;
  strncpy(unix_addr->sun_path, socket_name.c_str(), kMaxSocketNameLength);
  *unix_addr_len =
      offsetof(struct sockaddr_un, sun_path) + socket_name.length();
  return true;
}

bool IsRecoverableError(int err) {
  return errno == ECONNABORTED || errno == EMFILE || errno == ENFILE ||
         errno == ENOMEM || errno == ENOBUFS;
}

}  // namespace

bool CreateServerUnixDomainSocket(const base::FilePath& socket_path,
                                  int* server_listen_fd) {
  DCHECK(server_listen_fd);

  std::string socket_name = socket_path.value();
  base::FilePath socket_dir = socket_path.DirName();

  struct sockaddr_un unix_addr;
  size_t unix_addr_len;
  if (!MakeUnixAddrForPath(socket_name, &unix_addr, &unix_addr_len)) {
    return false;
  }

  base::ScopedFD fd;
  if (!CreateUnixDomainSocket(&fd)) {
    return false;
  }

  // Make sure the path we need exists.
  if (!base::CreateDirectory(socket_dir)) {
    LOGF(ERROR) << "Couldn't create directory: " << socket_dir.value();
    return false;
  }

  // Delete any old FS instances.
  if (unlink(socket_name.c_str()) < 0 && errno != ENOENT) {
    PLOGF(ERROR) << "unlink " << socket_name;
    return false;
  }

  // Bind the socket.
  if (bind(fd.get(), reinterpret_cast<const sockaddr*>(&unix_addr),
           unix_addr_len) < 0) {
    PLOGF(ERROR) << "bind " << socket_path.value();
    return false;
  }

  // Start listening on the socket.
  if (listen(fd.get(), SOMAXCONN) < 0) {
    PLOGF(ERROR) << "listen " << socket_path.value();
    unlink(socket_name.c_str());
    return false;
  }

  *server_listen_fd = fd.release();
  return true;
}

bool ServerAcceptConnection(int server_listen_fd, int* server_socket) {
  DCHECK(server_socket);
  *server_socket = -1;

  base::ScopedFD accept_fd(HANDLE_EINTR(accept(server_listen_fd, NULL, 0)));
  if (!accept_fd.is_valid())
    return IsRecoverableError(errno);
  if (HANDLE_EINTR(fcntl(accept_fd.get(), F_SETFL, O_NONBLOCK)) < 0) {
    PLOGF(ERROR) << "fcntl(O_NONBLOCK) " << accept_fd.get();
    // It's safe to keep listening on |server_listen_fd| even if the attempt to
    // set O_NONBLOCK failed on the client fd.
    return true;
  }

  *server_socket = accept_fd.release();
  return true;
}

base::ScopedFD CreateClientUnixDomainSocket(const base::FilePath& socket_path) {
  struct sockaddr_un unix_addr;
  size_t unix_addr_len;
  if (!MakeUnixAddrForPath(socket_path.value(), &unix_addr, &unix_addr_len))
    return base::ScopedFD();

  base::ScopedFD fd;
  if (!CreateUnixDomainSocket(&fd))
    return base::ScopedFD();

  if (HANDLE_EINTR(connect(fd.get(), reinterpret_cast<sockaddr*>(&unix_addr),
                           unix_addr_len)) < 0) {
    PLOGF(ERROR) << "connect " << socket_path.value();
    return base::ScopedFD();
  }

  // TODO(crbug.com/1053569): Remove these lines once the issue is solved.
  base::File::Info info;
  if (!base::GetFileInfo(socket_path, &info)) {
    LOGF(WARNING) << "Failed to get socket info";
  } else {
    LOGF(INFO) << "Connect the camera socket successfully. Socket info:"
               << " creation_time: " << info.creation_time
               << " last_accessed: " << info.last_accessed
               << " last_modified: " << info.last_modified;
  }
  return fd;
}

MojoResult CreateMojoChannelToParentByUnixDomainSocket(
    const base::FilePath& socket_path,
    mojo::ScopedMessagePipeHandle* child_pipe) {
  base::ScopedFD client_socket_fd = CreateClientUnixDomainSocket(socket_path);
  if (!client_socket_fd.is_valid()) {
    LOGF(WARNING) << "Failed to connect to " << socket_path.value();
    return MOJO_RESULT_INTERNAL;
  }

  // Set socket to blocking
  int flags = HANDLE_EINTR(fcntl(client_socket_fd.get(), F_GETFL));
  if (flags == -1) {
    PLOGF(ERROR) << "fcntl(F_GETFL) failed:";
    return MOJO_RESULT_INTERNAL;
  }
  if (HANDLE_EINTR(
          fcntl(client_socket_fd.get(), F_SETFL, flags & ~O_NONBLOCK)) == -1) {
    PLOGF(ERROR) << "fcntl(F_SETFL) failed:";
    return MOJO_RESULT_INTERNAL;
  }

  const int kTokenSize = 32;
  char token[kTokenSize] = {};
  std::vector<base::ScopedFD> platformHandles;
  ssize_t result =
      mojo::SocketRecvmsg(client_socket_fd.get(), token, sizeof(token),
                          &platformHandles, true /* block */);
  if (result != kTokenSize) {
    LOGF(ERROR) << "Unexpected read size: " << result;
    return MOJO_RESULT_INTERNAL;
  }
  mojo::IncomingInvitation invitation =
      mojo::IncomingInvitation::Accept(mojo::PlatformChannelEndpoint(
          mojo::PlatformHandle(std::move(platformHandles.back()))));
  platformHandles.pop_back();

  *child_pipe = invitation.ExtractMessagePipe(std::string(token, kTokenSize));

  return MOJO_RESULT_OK;
}

MojoResult CreateMojoChannelToChildByUnixDomainSocket(
    const base::FilePath& socket_path,
    mojo::ScopedMessagePipeHandle* parent_pipe,
    const std::string& pipe_name) {
  base::ScopedFD client_socket_fd = CreateClientUnixDomainSocket(socket_path);
  if (!client_socket_fd.is_valid()) {
    LOGF(WARNING) << "Failed to connect to " << socket_path.value();
    return MOJO_RESULT_INTERNAL;
  }

  VLOGF(1) << "Setting up message pipe";
  mojo::OutgoingInvitation invitation;
  mojo::PlatformChannel channel;

  mojo::ScopedMessagePipeHandle message_pipe =
      invitation.AttachMessagePipe(pipe_name);
  mojo::OutgoingInvitation::Send(std::move(invitation),
                                 base::kNullProcessHandle,
                                 channel.TakeLocalEndpoint());
  VLOGF(1) << "Invitation sent, message pipe: " << pipe_name;

  std::vector<base::ScopedFD> handles;
  handles.emplace_back(
      channel.TakeRemoteEndpoint().TakePlatformHandle().TakeFD());

  struct iovec iov = {const_cast<char*>(pipe_name.data()), pipe_name.size()};
  if (mojo::SendmsgWithHandles(client_socket_fd.get(), &iov, 1, handles) ==
      -1) {
    PLOGF(ERROR) << "Failed to send message and handle";
    return MOJO_RESULT_INTERNAL;
  }
  VLOGF(1) << "Message and handle sent";

  *parent_pipe = std::move(message_pipe);
  return MOJO_RESULT_OK;
}

std::optional<base::UnguessableToken> TokenFromString(
    const std::string& token_string) {
  if (token_string.length() != 32) {
    return std::nullopt;
  }
  std::string token_high_string = token_string.substr(0, 16);
  std::string token_low_string = token_string.substr(16, 16);
  uint64_t token_high, token_low;
  if (!base::HexStringToUInt64(token_high_string, &token_high) ||
      !base::HexStringToUInt64(token_low_string, &token_low)) {
    LOGF(ERROR) << "Failed to convert token strings";
    return std::nullopt;
  }
  return base::UnguessableToken::Deserialize(token_high, token_low);
}

}  // namespace cros
