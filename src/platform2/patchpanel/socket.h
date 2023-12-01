// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PATCHPANEL_SOCKET_H_
#define PATCHPANEL_SOCKET_H_

#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <memory>
#include <string>

#include <base/files/scoped_file.h>
#include <brillo/brillo_export.h>

namespace patchpanel {

// Wrapper around various syscalls used for socket communications.
class BRILLO_EXPORT Socket {
 public:
  Socket(int family, int type);
  explicit Socket(base::ScopedFD fd);
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;

  virtual ~Socket() = default;

  bool Bind(const struct sockaddr* addr, socklen_t addrlen);
  bool Connect(const struct sockaddr* addr, socklen_t addrlen);
  bool Listen(int backlog) const;
  std::unique_ptr<Socket> Accept(struct sockaddr* addr = nullptr,
                                 socklen_t* addrlen = nullptr) const;

  ssize_t SendTo(const void* data,
                 size_t len,
                 const struct sockaddr* addr = nullptr,
                 socklen_t addrlen = 0);
  ssize_t RecvFrom(void* data,
                   size_t len,
                   struct sockaddr* addr = nullptr,
                   socklen_t addrlen = 0);

  bool is_valid() const { return fd_.is_valid(); }

  int fd() const { return fd_.get(); }

  // Releases the underlying fd rendering the Socket instance invalid.
  int release() { return fd_.release(); }

 private:
  base::ScopedFD fd_;
};

BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const Socket& socket);

}  // namespace patchpanel

#endif  // PATCHPANEL_SOCKET_H_
