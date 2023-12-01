// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_MOCK_WIFI_H_
#define SHILL_WIFI_MOCK_WIFI_H_

#include <string>

#include <base/memory/ref_counted.h>
#include <gmock/gmock.h>

#include "shill/refptr_types.h"
#include "shill/store/key_value_store.h"
#include "shill/wifi/wake_on_wifi.h"
#include "shill/wifi/wifi.h"
#include "shill/wifi/wifi_endpoint.h"
#include "shill/wifi/wifi_service.h"

namespace shill {

class Error;

class MockWiFi : public WiFi {
 public:
  // MockWiFi takes ownership of the wake_on_wifi pointer passed to it.
  // This is not exposed in the constructor type because gmock doesn't
  // provide the ability to forward arguments that aren't const &...
  MockWiFi(Manager* manager,
           const std::string& link_name,
           const std::string& address,
           int interface_index,
           uint32_t phy_index,
           WakeOnWiFiInterface* wake_on_wifi);
  MockWiFi(const MockWiFi&) = delete;
  MockWiFi& operator=(const MockWiFi&) = delete;

  ~MockWiFi() override;

  MOCK_METHOD(void, Start, (EnabledStateChangedCallback), (override));
  MOCK_METHOD(void, Stop, (EnabledStateChangedCallback), (override));
  MOCK_METHOD(void, Scan, (Error*, const std::string&), (override));
  MOCK_METHOD(void, Restart, (), (override));
  MOCK_METHOD(void, DisconnectFromIfActive, (WiFiService*), (override));
  MOCK_METHOD(void, DisconnectFrom, (WiFiService*), (override));
  MOCK_METHOD(void, ClearCachedCredentials, (const WiFiService*), (override));
  MOCK_METHOD(void,
              ConnectTo,
              (WiFiService * service, Error* error),
              (override));
  MOCK_METHOD(bool, IsIdle, (), (const, override));
  MOCK_METHOD(void,
              NotifyEndpointChanged,
              (const WiFiEndpointConstRefPtr&),
              (override));
  MOCK_METHOD(bool, IsCurrentService, (const WiFiService* service), (const));
  MOCK_METHOD(int16_t, GetSignalLevelForActiveService, (), (override));
  MOCK_METHOD(void,
              EmitStationInfoRequestEvent,
              (WiFiLinkStatistics::Trigger trigger),
              (override));
  MOCK_METHOD(bool,
              SetBSSIDAllowlist,
              (const WiFiService* service,
               const Strings& bssid_allowlist,
               Error* error),
              (override));
};

}  // namespace shill

#endif  // SHILL_WIFI_MOCK_WIFI_H_
