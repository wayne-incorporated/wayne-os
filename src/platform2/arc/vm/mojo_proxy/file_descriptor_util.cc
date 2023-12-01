// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/mojo_proxy/file_descriptor_util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <base/check_op.h>

// Needs to be included after sys/socket.h
#include <linux/un.h>

#include <optional>

#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <brillo/files/file_util.h>

namespace arc {
namespace {

// SCM_MAX_FD value currently used by the kernel.
constexpr size_t kMaxNumFileDescriptors = 253;

bool ToSockAddr(const base::FilePath& path, struct sockaddr_un* sa) {
  // sun_path needs to include trailing '\0' byte.
  if (path.value().size() >= sizeof(sa->sun_path)) {
    LOG(ERROR) << "Path is too long: " << path.value();
    return false;
  }

  memset(sa, 0, sizeof(*sa));
  sa->sun_family = AF_UNIX;
  strncpy(sa->sun_path, path.value().c_str(), sizeof(sa->sun_path) - 1);
  return true;
}

}  // namespace

std::optional<std::pair<base::ScopedFD, base::ScopedFD>> CreatePipe() {
  int fds[2];
  if (pipe2(fds, O_CLOEXEC | O_NONBLOCK) == -1) {
    PLOG(ERROR) << "Failed to create pipe";
    return std::nullopt;
  }

  return std::make_optional(
      std::make_pair(base::ScopedFD(fds[0]), base::ScopedFD(fds[1])));
}

std::optional<std::pair<base::ScopedFD, base::ScopedFD>> CreateSocketPair(
    int type) {
  int fds[2];
  if (socketpair(AF_UNIX, type | SOCK_CLOEXEC, 0 /* protocol */, fds) == -1) {
    PLOG(ERROR) << "Failed to create socketpair";
    return std::nullopt;
  }

  return std::make_optional(
      std::make_pair(base::ScopedFD(fds[0]), base::ScopedFD(fds[1])));
}

base::ScopedFD CreateUnixDomainSocket(const base::FilePath& path) {
  LOG(INFO) << "Creating " << path.value();

  struct sockaddr_un sa;
  if (!ToSockAddr(path, &sa))
    return {};

  base::ScopedFD fd(
      socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0 /* protocol */));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to create unix domain socket";
    return {};
  }

  // Remove stale file first. Ignore the error intentionally.
  brillo::DeleteFile(path);

  if (bind(fd.get(), reinterpret_cast<const struct sockaddr*>(&sa),
           sizeof(sa)) == -1) {
    PLOG(ERROR) << "Failed to bind a unix domain socket";
    return {};
  }

  if (fchmod(fd.get(), 0666) == -1) {
    PLOG(ERROR) << "Failed to set permission";
    return {};
  }

  if (listen(fd.get(), 5 /* backlog */) == -1) {
    PLOG(ERROR) << "Failed to start listening a socket";
    return {};
  }

  LOG(INFO) << path.value() << " created.";
  return fd;
}

base::ScopedFD AcceptSocket(int raw_fd) {
  base::ScopedFD fd(
      HANDLE_EINTR(accept4(raw_fd, nullptr, nullptr, SOCK_CLOEXEC)));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to accept() unix domain socket";
    return {};
  }
  return fd;
}

std::pair<int, base::ScopedFD> ConnectUnixDomainSocket(
    const base::FilePath& path) {
  LOG(INFO) << "Connecting to " << path.value();

  struct sockaddr_un sa;
  if (!ToSockAddr(path, &sa))
    return std::make_pair(EFAULT, base::ScopedFD());

  base::ScopedFD fd(
      socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0 /* protocol */));
  if (!fd.is_valid()) {
    int result_errno = errno;
    PLOG(ERROR) << "Failed to create unix domain socket";
    return std::make_pair(result_errno, base::ScopedFD());
  }

  if (HANDLE_EINTR(connect(fd.get(),
                           reinterpret_cast<const struct sockaddr*>(&sa),
                           sizeof(sa))) == -1) {
    int result_errno = errno;
    PLOG(ERROR) << "Failed to connect.";
    return std::make_pair(result_errno, base::ScopedFD());
  }

  LOG(INFO) << "Connected to " << path.value();
  return std::make_pair(0, std::move(fd));
}

int GetSocketType(int fd) {
  int type = 0;
  socklen_t length = sizeof(type);
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &length) == -1) {
    PLOG(ERROR) << "getsockopt failed";
    return -1;
  }
  return type;
}

ssize_t Sendmsg(int fd,
                const void* buf,
                size_t length,
                const std::vector<base::ScopedFD>& fds) {
  if (fds.size() >= kMaxNumFileDescriptors) {
    LOG(ERROR) << "Too many FDs: " << fds.size();
    errno = EINVAL;
    return -1;
  }
  char control_buffer[CMSG_SPACE(kMaxNumFileDescriptors * sizeof(int))];
  struct iovec iov = {const_cast<void*>(buf), length};
  struct msghdr msg = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control_buffer,
      .msg_controllen = CMSG_SPACE(fds.size() * sizeof(int)),
  };
  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(fds.size() * sizeof(int));
  for (size_t i = 0; i != fds.size(); ++i)
    reinterpret_cast<int*>(CMSG_DATA(cmsg))[i] = fds[i].get();
  return HANDLE_EINTR(sendmsg(fd, &msg, MSG_NOSIGNAL));
}

ssize_t Recvmsg(int fd,
                void* buf,
                size_t length,
                std::vector<base::ScopedFD>* fds) {
  fds->clear();

  char control_buffer[CMSG_SPACE(kMaxNumFileDescriptors * sizeof(int))];
  struct iovec iov = {buf, length};
  struct msghdr msg = {
      .msg_iov = &iov,
      .msg_iovlen = 1,
      .msg_control = control_buffer,
      .msg_controllen = sizeof(control_buffer),
  };
  const ssize_t result = HANDLE_EINTR(recvmsg(fd, &msg, 0));
  if (result < 0)  // Failed.
    return result;

  if (msg.msg_controllen > 0) {
    // Extract file descriptors from the control data.
    for (struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
      if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        const size_t payload_length = cmsg->cmsg_len - CMSG_LEN(0);
        DCHECK_EQ(payload_length % sizeof(int), 0u);
        const size_t n_fds = payload_length / sizeof(int);
        const int* data = reinterpret_cast<int*>(CMSG_DATA(cmsg));
        fds->reserve(n_fds);
        for (size_t i = 0; i < n_fds; ++i)
          fds->emplace_back(data[i]);
      }
    }
  }

  if (msg.msg_flags & MSG_TRUNC) {
    LOG(ERROR) << "Datagram larger than the data buffer.";
    errno = EMSGSIZE;
    return -1;
  }
  if (msg.msg_flags & MSG_CTRUNC) {
    LOG(ERROR) << "Control data larger than the control buffer.";
    errno = EMSGSIZE;
    return -1;
  }

  return result;
}

}  // namespace arc
