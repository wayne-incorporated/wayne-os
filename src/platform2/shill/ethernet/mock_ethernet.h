// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_MOCK_ETHERNET_H_
#define SHILL_ETHERNET_MOCK_ETHERNET_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/ethernet/ethernet.h"
#include "shill/refptr_types.h"

namespace shill {

class Error;

class MockEthernet : public Ethernet {
 public:
  MockEthernet(Manager* manager,
               const std::string& link_name,
               const std::string& address,
               int interface_index);
  MockEthernet(const MockEthernet&) = delete;
  MockEthernet& operator=(const MockEthernet&) = delete;

  ~MockEthernet() override;

  MOCK_METHOD(void, Start, (EnabledStateChangedCallback), (override));
  MOCK_METHOD(void, Stop, (EnabledStateChangedCallback), (override));
  MOCK_METHOD(void, ConnectTo, (EthernetService*), (override));
  MOCK_METHOD(void, DisconnectFrom, (EthernetService*), (override));
  MOCK_METHOD(bool, link_up, (), (const, override));
};

}  // namespace shill

#endif  // SHILL_ETHERNET_MOCK_ETHERNET_H_
