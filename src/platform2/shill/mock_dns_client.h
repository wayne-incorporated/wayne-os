// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_DNS_CLIENT_H_
#define SHILL_MOCK_DNS_CLIENT_H_

#include <string>
#include <vector>

#include "shill/dns_client.h"

#include <gmock/gmock.h>

namespace shill {

class MockDnsClient : public DnsClient {
 public:
  MockDnsClient();
  MockDnsClient(const MockDnsClient&) = delete;
  MockDnsClient& operator=(const MockDnsClient&) = delete;

  ~MockDnsClient() override;

  MOCK_METHOD(bool,
              Start,
              (const std::vector<std::string>&, const std::string&, Error*),
              (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(bool, IsActive, (), (const, override));
};

}  // namespace shill

#endif  // SHILL_MOCK_DNS_CLIENT_H_
