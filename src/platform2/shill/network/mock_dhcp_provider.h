// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_MOCK_DHCP_PROVIDER_H_
#define SHILL_NETWORK_MOCK_DHCP_PROVIDER_H_

#include <memory>
#include <string>

#include <gmock/gmock.h>

#include "shill/network/dhcp_controller.h"
#include "shill/network/dhcp_provider.h"
#include "shill/refptr_types.h"

namespace shill {

class ControlInterface;
class EventDispatcher;
class Metrics;

class MockDHCPProvider : public DHCPProvider {
 public:
  MockDHCPProvider();
  MockDHCPProvider(const MockDHCPProvider&) = delete;
  MockDHCPProvider& operator=(const MockDHCPProvider&) = delete;

  ~MockDHCPProvider() override;

  MOCK_METHOD(void,
              Init,
              (ControlInterface*, EventDispatcher*, Metrics*),
              (override));
  MOCK_METHOD(std::unique_ptr<DHCPController>,
              CreateController,
              (const std::string&, const DHCPProvider::Options&, Technology),
              (override));
  MOCK_METHOD(void, BindPID, (int, base::WeakPtr<DHCPController>), (override));
  MOCK_METHOD(void, UnbindPID, (int), (override));
};

}  // namespace shill

#endif  // SHILL_NETWORK_MOCK_DHCP_PROVIDER_H_
