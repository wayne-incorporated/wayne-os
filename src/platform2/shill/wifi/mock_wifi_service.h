// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_MOCK_WIFI_SERVICE_H_
#define SHILL_WIFI_MOCK_WIFI_SERVICE_H_

#include <set>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/wifi/wifi_endpoint.h"
#include "shill/wifi/wifi_service.h"

namespace shill {

class MockWiFiService : public WiFiService {
 public:
  MockWiFiService(Manager* manager,
                  WiFiProvider* provider,
                  const std::vector<uint8_t>& ssid,
                  const std::string& mode,
                  const std::string& security_class,
                  const WiFiSecurity& security,
                  bool hidden_ssid);
  MockWiFiService(const MockWiFiService&) = delete;
  MockWiFiService& operator=(const MockWiFiService&) = delete;

  ~MockWiFiService() override;

  MOCK_METHOD(void, Configure, (const KeyValueStore&, Error*), (override));
  MOCK_METHOD(void, SetFailure, (ConnectFailure), (override));
  MOCK_METHOD(void, SetFailureSilent, (ConnectFailure), (override));
  MOCK_METHOD(void, SetState, (ConnectState), (override));
  MOCK_METHOD(void, ResetAutoConnectCooldownTime, (), (override));
  MOCK_METHOD(bool,
              AddEAPCertification,
              (const std::string&, size_t),
              (override));
  MOCK_METHOD(bool, HasRecentConnectionIssues, (), (override));
  MOCK_METHOD(bool, AddAndCheckSuspectedCredentialFailure, (), (override));
  MOCK_METHOD(void, AddSuspectedCredentialFailure, (), (override));
  MOCK_METHOD(bool, CheckSuspectedCredentialFailure, (), (override));
  MOCK_METHOD(void, ResetSuspectedCredentialFailures, (), (override));
  MOCK_METHOD(void, AddEndpoint, (const WiFiEndpointConstRefPtr&), (override));
  MOCK_METHOD(void,
              RemoveEndpoint,
              (const WiFiEndpointConstRefPtr&),
              (override));
  MOCK_METHOD(void,
              NotifyCurrentEndpoint,
              (const WiFiEndpointConstRefPtr&),
              (override));
  MOCK_METHOD(void,
              NotifyEndpointUpdated,
              (const WiFiEndpointConstRefPtr&),
              (override));
  MOCK_METHOD(void,
              DisconnectWithFailure,
              (ConnectFailure, Error*, const char*),
              (override));
  MOCK_METHOD(void, Disconnect, (Error*, const char*), (override));
  MOCK_METHOD(bool, IsActive, (Error*), (const, override));
  MOCK_METHOD(bool, IsConnected, (Error*), (const, override));
  MOCK_METHOD(bool, IsConnecting, (), (const, override));
  MOCK_METHOD(bool, HasEndpoints, (), (const, override));
  MOCK_METHOD(bool, HasBSSIDConnectableEndpoints, (), (const, override));
  MOCK_METHOD(int, GetBSSIDConnectableEndpointCount, (), (const, override));
  MOCK_METHOD(bool, IsRemembered, (), (const, override));
  MOCK_METHOD(void, ResetWiFi, (), (override));
  MOCK_METHOD(KeyValueStore,
              GetSupplicantConfigurationParameters,
              (),
              (const, override));
  MOCK_METHOD(bool, IsAutoConnectable, (const char**), (const, override));
  MOCK_METHOD(bool, ShouldIgnoreFailure, (), (const, override));
  MOCK_METHOD(bool, link_monitor_disabled, (), (const, override));
  MOCK_METHOD(int16_t, SignalLevel, (), (const, override));
  MOCK_METHOD(void,
              EmitDisconnectionEvent,
              (Metrics::WiFiDisconnectionType, IEEE_80211::WiFiReasonCode),
              (override));
  MOCK_METHOD(void,
              EmitLinkQualityTriggerEvent,
              (Metrics::WiFiLinkQualityTrigger),
              (const, override));
  MOCK_METHOD(void,
              EmitLinkQualityReportEvent,
              (const Metrics::WiFiLinkQualityReport&),
              (const, override));
  MOCK_METHOD(void, SetUplinkSpeedKbps, (uint32_t), (override));
  MOCK_METHOD(void, SetDownlinkSpeedKbps, (uint32_t), (override));
  MOCK_METHOD(void, Connect, (Error*, const char*), (override));
};

}  // namespace shill

#endif  // SHILL_WIFI_MOCK_WIFI_SERVICE_H_
