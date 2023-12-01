// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_ICMP_SESSION_H_
#define SHILL_MOCK_ICMP_SESSION_H_

#include "shill/icmp_session.h"

#include <gmock/gmock.h>

#include "shill/net/ip_address.h"

namespace shill {

class MockIcmpSession : public IcmpSession {
 public:
  explicit MockIcmpSession(EventDispatcher* dispatcher);
  MockIcmpSession(const MockIcmpSession&) = delete;
  MockIcmpSession& operator=(const MockIcmpSession&) = delete;

  ~MockIcmpSession() override;

  MOCK_METHOD(bool,
              Start,
              (const IPAddress&, int, IcmpSession::IcmpSessionResultCallback),
              (override));
  MOCK_METHOD(void, Stop, (), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_ICMP_SESSION_H_
