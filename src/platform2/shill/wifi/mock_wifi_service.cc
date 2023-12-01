// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/wifi/mock_wifi_service.h"

namespace shill {

class ControlInterface;
class EventDispatcher;
class Manager;

using testing::WithArg;

MockWiFiService::MockWiFiService(Manager* manager,
                                 WiFiProvider* provider,
                                 const std::vector<uint8_t>& ssid,
                                 const std::string& mode,
                                 const std::string& security_class,
                                 const WiFiSecurity& security,
                                 bool hidden_ssid)
    : WiFiService(manager,
                  provider,
                  ssid,
                  mode,
                  security_class,
                  security,
                  hidden_ssid) {
  ON_CALL(*this, GetSupplicantConfigurationParameters())
      .WillByDefault(testing::Return(KeyValueStore()));
  // For SetState() by default just call the implementation.
  ON_CALL(*this, SetState).WillByDefault(WithArg<0>([this](auto state) {
    this->WiFiService::SetState(state);
  }));
}

MockWiFiService::~MockWiFiService() = default;

}  // namespace shill
