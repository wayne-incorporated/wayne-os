// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_ARES_H_
#define SHILL_MOCK_ARES_H_

#include <gmock/gmock.h>

#include "shill/shill_ares.h"

namespace shill {

class MockAres : public Ares {
 public:
  MockAres();
  MockAres(const MockAres&) = delete;
  MockAres& operator=(const MockAres&) = delete;

  ~MockAres() override;

  MOCK_METHOD(void, Destroy, (ares_channel), (override));
  MOCK_METHOD(void,
              GetHostByName,
              (ares_channel, const char*, int, ares_host_callback, void*),
              (override));
  MOCK_METHOD(int, GetSock, (ares_channel, ares_socket_t*, int), (override));
  MOCK_METHOD(int,
              InitOptions,
              (ares_channel*, struct ares_options*, int),
              (override));
  MOCK_METHOD(void,
              ProcessFd,
              (ares_channel, ares_socket_t, ares_socket_t),
              (override));
  MOCK_METHOD(void, SetLocalDev, (ares_channel, const char*), (override));
  MOCK_METHOD(struct timeval*,
              Timeout,
              (ares_channel, struct timeval*, struct timeval*),
              (override));
  MOCK_METHOD(int, SetServersCsv, (ares_channel, const char*), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_ARES_H_
