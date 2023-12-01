// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_CONNECTION_H_
#define SHILL_MOCK_CONNECTION_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/connection.h"
#include "shill/network/network_priority.h"

namespace shill {

class MockConnection : public Connection {
 public:
  MockConnection();
  MockConnection(const MockConnection&) = delete;
  MockConnection& operator=(const MockConnection&) = delete;

  ~MockConnection() override;

  MOCK_METHOD(void,
              UpdateFromIPConfig,
              (const IPConfig::Properties& properties),
              (override));
  MOCK_METHOD(void, SetPriority, (NetworkPriority), (override));
  MOCK_METHOD(const std::string&, interface_name, (), (const, override));
  MOCK_METHOD(bool, IsIPv6, (), (override));
};

}  // namespace shill

#endif  // SHILL_MOCK_CONNECTION_H_
