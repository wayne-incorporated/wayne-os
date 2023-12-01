// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_MOCK_DHCP_CONTROLLER_H_
#define SHILL_NETWORK_MOCK_DHCP_CONTROLLER_H_

#include <optional>
#include <string>

#include <gmock/gmock.h>

#include "shill/network/dhcp_controller.h"
#include "shill/technology.h"

namespace shill {

class MockDHCPController : public DHCPController {
 public:
  MockDHCPController(ControlInterface* control_interface,
                     const std::string& device_name);
  MockDHCPController(const MockDHCPController&) = delete;
  MockDHCPController& operator=(const MockDHCPController&) = delete;

  ~MockDHCPController() override;

  void RegisterCallbacks(UpdateCallback update_callback,
                         DropCallback drop_callback) override;
  void TriggerUpdateCallback(const IPConfig::Properties& props);
  void TriggerDropCallback(bool is_voluntary);
  void ProcessEventSignal(ClientEventReason reason,
                          const KeyValueStore& configuration) override;

  MOCK_METHOD(bool, RequestIP, (), (override));
  MOCK_METHOD(bool, ReleaseIP, (ReleaseReason), (override));
  MOCK_METHOD(bool, RenewIP, (), (override));
  MOCK_METHOD(std::optional<base::TimeDelta>,
              TimeToLeaseExpiry,
              (),
              (override));

 private:
  UpdateCallback update_callback_;
  DropCallback drop_callback_;
};

}  // namespace shill

#endif  // SHILL_NETWORK_MOCK_DHCP_CONTROLLER_H_
