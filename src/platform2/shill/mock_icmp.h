// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_ICMP_H_
#define SHILL_MOCK_ICMP_H_

#include "shill/icmp.h"

#include <gmock/gmock.h>

#include "shill/net/ip_address.h"

namespace shill {

class MockIcmp : public Icmp {
 public:
  MockIcmp();
  MockIcmp(const MockIcmp&) = delete;
  MockIcmp& operator=(const MockIcmp&) = delete;

  ~MockIcmp() override;

  MOCK_METHOD(bool, Start, (const IPAddress&, int), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(bool, IsStarted, (), (const, override));
  MOCK_METHOD(bool, TransmitEchoRequest, (uint16_t, uint16_t), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_ICMP_H_
