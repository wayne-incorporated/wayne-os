// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "patchpanel/socket.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <utility>

#include <base/logging.h>
#include <base/memory/ptr_util.h>

#include "patchpanel/net_util.h"

namespace patchpanel {
namespace {

bool WouldBlock() {
  return errno == EAGAIN || errno == EWOULDBLOCK;
}
}  // namespace

Socket::Socket(int family, int type) : fd_(socket(family, type, 0)) {}

Socket::Socket(base::ScopedFD fd) : fd_(std::move(fd)) {}

bool Socket::Bind(const struct sockaddr* addr, socklen_t addrlen) {
  return bind(fd_.get(), addr, addrlen) == 0;
}

bool Socket::Connect(const struct sockaddr* addr, socklen_t addrlen) {
  return connect(fd_.get(), addr, addrlen) == 0;
}

bool Socket::Listen(int backlog) const {
  return listen(fd_.get(), backlog) == 0;
}

std::unique_ptr<Socket> Socket::Accept(struct sockaddr* addr,
                                       socklen_t* addrlen) const {
  base::ScopedFD fd(accept(fd_.get(), addr, addrlen));
  if (!fd.is_valid()) {
    return nullptr;
  }
  return std::make_unique<Socket>(std::move(fd));
}

ssize_t Socket::SendTo(const void* data,
                       size_t len,
                       const struct sockaddr* addr,
                       socklen_t addrlen) {
  if (!fd_.is_valid()) {
    return -1;
  }
  if (!addr) {
    addrlen = 0;
  } else if (addrlen == 0) {
    addrlen = sizeof(*addr);
  }

  ssize_t bytes = sendto(fd_.get(), data, len, MSG_NOSIGNAL, addr, addrlen);
  if (bytes >= 0)
    return bytes;

  if (WouldBlock())
    return 0;

  return bytes;
}

ssize_t Socket::RecvFrom(void* data,
                         size_t len,
                         struct sockaddr* addr,
                         socklen_t addrlen) {
  socklen_t recvlen = addrlen;
  ssize_t bytes = recvfrom(fd_.get(), data, len, 0, addr, &recvlen);
  if (bytes >= 0) {
    if (recvlen != addrlen)
      LOG(WARNING) << "recvfrom failed: unexpected src addr length " << recvlen;
    return bytes;
  }

  if (WouldBlock())
    return 0;

  return bytes;
}

std::ostream& operator<<(std::ostream& stream, const Socket& socket) {
  stream << "{fd: " << socket.fd() << "}";
  return stream;
}

}  // namespace patchpanel
