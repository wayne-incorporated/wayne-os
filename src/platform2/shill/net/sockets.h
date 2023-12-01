// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_SOCKETS_H_
#define SHILL_NET_SOCKETS_H_

#include <linux/filter.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <string>

#include "shill/net/shill_export.h"

namespace shill {

// A "sys/socket.h" abstraction allowing mocking in tests.
class SHILL_EXPORT Sockets {
 public:
  Sockets();
  Sockets(const Sockets&) = delete;
  Sockets& operator=(const Sockets&) = delete;

  virtual ~Sockets();

  static const int kInvalidFileDescriptor = -1;

  // accept
  virtual int Accept(int sockfd,
                     struct sockaddr* addr,
                     socklen_t* addrlen) const;

  // getsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, ...)
  virtual int AttachFilter(int sockfd, struct sock_fprog* pf) const;

  // bind
  virtual int Bind(int sockfd,
                   const struct sockaddr* addr,
                   socklen_t addrlen) const;

  // setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE ...)
  virtual int BindToDevice(int sockfd, const std::string& device) const;

  // setsockopt(s, SOL_SOCKET, SO_REUSEADDR, ...)
  virtual int ReuseAddress(int sockfd) const;

  // setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, ...)
  virtual int AddMulticastMembership(int sockfd, in_addr_t addr) const;

  // close
  virtual int Close(int fd) const;

  // connect
  virtual int Connect(int sockfd,
                      const struct sockaddr* addr,
                      socklen_t addrlen) const;

  // getsockname
  virtual int GetSockName(int sockfd,
                          struct sockaddr* addr,
                          socklen_t* addrlen) const;

  // getsockopt(sockfd, SOL_SOCKET, SO_ERROR, ...)
  virtual int GetSocketError(int sockfd) const;

  // ioctl
  virtual int Ioctl(int d, int request, void* argp) const;

  // listen
  virtual int Listen(int sockfd, int backlog) const;

  // recvfrom
  virtual ssize_t RecvFrom(int sockfd,
                           void* buf,
                           size_t len,
                           int flags,
                           struct sockaddr* src_addr,
                           socklen_t* addrlen) const;

  // select
  virtual int Select(int nfds,
                     fd_set* readfds,
                     fd_set* writefds,
                     fd_set* exceptfds,
                     struct timeval* timeout) const;

  // send
  virtual ssize_t Send(int sockfd,
                       const void* buf,
                       size_t len,
                       int flags) const;

  // sendto
  virtual ssize_t SendTo(int sockfd,
                         const void* buf,
                         size_t len,
                         int flags,
                         const struct sockaddr* dest_addr,
                         socklen_t addrlen) const;

  // fcntl(sk, F_SETFL, fcntl(sk, F_GETFL) | O_NONBLOCK)
  virtual int SetNonBlocking(int sockfd) const;

  // setsockopt(SO_RCVBUFFORCE)
  virtual int SetReceiveBuffer(int sockfd, int size) const;

  // socket
  virtual int Socket(int domain, int type, int protocol) const;
};

class SHILL_EXPORT ScopedSocketCloser {
 public:
  ScopedSocketCloser(Sockets* sockets, int fd);
  ScopedSocketCloser(const ScopedSocketCloser&) = delete;
  ScopedSocketCloser& operator=(const ScopedSocketCloser&) = delete;

  ~ScopedSocketCloser();

  // Release and return the socket file descriptor, allowing the socket to
  // remain open as the ScopedSocketCloser is destroyed.
  [[nodiscard]] int Release();

 private:
  Sockets* sockets_;
  int fd_;
};

}  // namespace shill

#endif  // SHILL_NET_SOCKETS_H_
