// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NET_MOCK_SOCKETS_H_
#define SHILL_NET_MOCK_SOCKETS_H_

#include <string>

#include "shill/net/sockets.h"

#include <gmock/gmock.h>

namespace shill {

class MockSockets : public Sockets {
 public:
  MockSockets();
  MockSockets(const MockSockets&) = delete;
  MockSockets& operator=(const MockSockets&) = delete;

  ~MockSockets() override;

  MOCK_METHOD(int,
              Accept,
              (int, struct sockaddr*, socklen_t*),
              (const, override));
  MOCK_METHOD(int, AttachFilter, (int, struct sock_fprog*), (const, override));
  MOCK_METHOD(int,
              Bind,
              (int, const struct sockaddr*, socklen_t),
              (const, override));
  MOCK_METHOD(int, BindToDevice, (int, const std::string&), (const, override));
  MOCK_METHOD(int, ReuseAddress, (int), (const, override));
  MOCK_METHOD(int, AddMulticastMembership, (int, in_addr_t), (const, override));
  MOCK_METHOD(int, Close, (int fd), (const, override));
  MOCK_METHOD(int,
              Connect,
              (int, const struct sockaddr*, socklen_t),
              (const, override));
  MOCK_METHOD(int,
              GetSockName,
              (int, struct sockaddr*, socklen_t*),
              (const, override));
  MOCK_METHOD(int, GetSocketError, (int), (const, override));
  MOCK_METHOD(int, Ioctl, (int, int, void*), (const, override));
  MOCK_METHOD(int, Listen, (int, int), (const, override));
  MOCK_METHOD(ssize_t,
              RecvFrom,
              (int, void*, size_t, int, struct sockaddr*, socklen_t*),
              (const, override));
  MOCK_METHOD(int,
              Select,
              (int, fd_set*, fd_set*, fd_set*, struct timeval*),
              (const, override));
  MOCK_METHOD(ssize_t,
              Send,
              (int, const void*, size_t, int),
              (const, override));
  MOCK_METHOD(
      ssize_t,
      SendTo,
      (int, const void*, size_t, int, const struct sockaddr*, socklen_t),
      (const, override));
  MOCK_METHOD(int, SetNonBlocking, (int), (const, override));
  MOCK_METHOD(int, SetReceiveBuffer, (int, int), (const, override));
  MOCK_METHOD(int, Socket, (int, int, int), (const, override));
};

}  // namespace shill

#endif  // SHILL_NET_MOCK_SOCKETS_H_
