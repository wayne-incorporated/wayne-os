// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/boot_notification_server/util.h"

#include <linux/vm_sockets.h>
#include <string.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <optional>

#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_number_conversions.h>
#include <re2/re2.h>

constexpr size_t kChunkSize = 256;

socklen_t GetSockLen(sa_family_t family) {
  switch (family) {
    case AF_VSOCK:
      return sizeof(sockaddr_vm);
    case AF_UNIX:
      return sizeof(sockaddr_un);
    default:
      LOG(ERROR) << "Using unsupported socket type " << family;
      return sizeof(sockaddr);
  }
}

base::ScopedFD StartListening(sockaddr* addr) {
  LOG(INFO) << "Creating socket";
  base::ScopedFD fd(
      socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0 /* protocol */));
  if (!fd.is_valid()) {
    PLOG(ERROR) << "Failed to create socket";
    return {};
  }

  LOG(INFO) << "Binding socket";
  if (HANDLE_EINTR(bind(fd.get(), addr, GetSockLen(addr->sa_family))) == -1) {
    PLOG(ERROR) << "Failed to bind to socket address";
    return {};
  }

  LOG(INFO) << "Listening on socket";
  if (HANDLE_EINTR(listen(fd.get(), 5 /* backlog */)) == -1) {
    PLOG(ERROR) << "Failed to listen to socket";
    return {};
  }

  return fd;
}

base::ScopedFD WaitForClientConnect(int fd) {
  LOG(INFO) << "Waiting for client to connect";
  base::ScopedFD client_fd(HANDLE_EINTR(accept(fd, nullptr, nullptr)));
  if (!client_fd.is_valid()) {
    PLOG(ERROR) << "Failed to accept connection on socket";
    return {};
  }

  LOG(INFO) << "Client connected";
  return client_fd;
}

std::optional<std::string> ReadFD(int fd) {
  std::string out;
  char buf[kChunkSize];

  while (true) {
    ssize_t len = HANDLE_EINTR(read(fd, buf, kChunkSize));
    if (len == -1) {
      PLOG(ERROR) << "Unable to read from fd " << fd;
      return std::nullopt;
    }
    if (len == 0)
      break;

    out.append(buf, len);
  }

  if (out.empty())
    return std::nullopt;

  return out;
}

std::optional<std::pair<unsigned int, std::string>> ExtractCidValue(
    const std::string& props) {
  // Pattern to extract CID from props string. `(?s)` flag is needed to let `.`
  // match newlines.
  static const re2::RE2& pattern = *new re2::RE2("(?s)^CID=(\\d+)\n(.*)$");
  unsigned int cid;
  std::string tail;
  if (!re2::RE2::FullMatch(props, pattern, &cid, &tail)) {
    LOG(ERROR) << "The input '" << props
               << "' did not match the expected pattern";
    return std::nullopt;
  }
  return std::make_pair(cid, tail);
}

std::optional<unsigned int> GetPeerCid(int fd) {
  sockaddr_vm addr;
  socklen_t len = sizeof(sockaddr_vm);
  if (getpeername(fd, reinterpret_cast<sockaddr*>(&addr), &len) == -1) {
    PLOG(ERROR) << "Unable to get peer address from socket fd " << fd;
    return std::nullopt;
  }
  return addr.svm_cid;
}
