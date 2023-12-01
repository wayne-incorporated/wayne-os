// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_WIFI_MOCK_WIFI_PROVIDER_H_
#define SHILL_WIFI_MOCK_WIFI_PROVIDER_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/manager.h"
#include "shill/wifi/hotspot_device.h"
#include "shill/wifi/local_device.h"
#include "shill/wifi/passpoint_credentials.h"
#include "shill/wifi/wifi_endpoint.h"
#include "shill/wifi/wifi_phy.h"
#include "shill/wifi/wifi_provider.h"
#include "shill/wifi/wifi_service.h"

namespace shill {

class MockWiFiProvider : public WiFiProvider {
 public:
  explicit MockWiFiProvider(Manager* manager);
  MockWiFiProvider(const MockWiFiProvider&) = delete;
  MockWiFiProvider& operator=(const MockWiFiProvider&) = delete;

  ~MockWiFiProvider() override;

  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void,
              CreateServicesFromProfile,
              (const ProfileRefPtr&),
              (override));
  MOCK_METHOD(ServiceRefPtr,
              FindSimilarService,
              (const KeyValueStore&, Error*),
              (const, override));
  MOCK_METHOD(ServiceRefPtr,
              CreateTemporaryService,
              (const KeyValueStore&, Error*),
              (override));
  MOCK_METHOD(ServiceRefPtr,
              GetService,
              (const KeyValueStore&, Error*),
              (override));
  MOCK_METHOD(WiFiServiceRefPtr,
              FindServiceForEndpoint,
              (const WiFiEndpointConstRefPtr&),
              (override));
  MOCK_METHOD(bool,
              OnEndpointAdded,
              (const WiFiEndpointConstRefPtr&),
              (override));
  MOCK_METHOD(WiFiServiceRefPtr,
              OnEndpointRemoved,
              (const WiFiEndpointConstRefPtr&),
              (override));
  MOCK_METHOD(void,
              OnEndpointUpdated,
              (const WiFiEndpointConstRefPtr&),
              (override));
  MOCK_METHOD(bool,
              OnServiceUnloaded,
              (const WiFiServiceRefPtr&, const PasspointCredentialsRefPtr&),
              (override));
  MOCK_METHOD(ByteArrays, GetHiddenSSIDList, (), (override));
  MOCK_METHOD(int, NumAutoConnectableServices, (), (override));
  MOCK_METHOD(void, ResetServicesAutoConnectCooldownTime, (), (override));
  MOCK_METHOD(void,
              AddCredentials,
              (const PasspointCredentialsRefPtr&),
              (override));
  MOCK_METHOD(std::vector<PasspointCredentialsRefPtr>,
              GetCredentials,
              (),
              (override));
  MOCK_METHOD(PasspointCredentialsRefPtr,
              FindCredentials,
              (const std::string&),
              (override));
  MOCK_METHOD(void,
              OnPasspointCredentialsMatches,
              (const std::vector<PasspointMatch>&),
              (override));
  MOCK_METHOD(void,
              OnNewWiphy,
              (const Nl80211Message& nl80211_message),
              (override));
  MOCK_METHOD(const WiFiPhy*, GetPhyAtIndex, (uint32_t), (override));
  MOCK_METHOD(std::vector<const WiFiPhy*>, GetPhys, (), (const, override));
  MOCK_METHOD(void,
              RegisterDeviceToPhy,
              (WiFiConstRefPtr, uint32_t),
              (override));
  MOCK_METHOD(void,
              DeregisterDeviceFromPhy,
              (WiFiConstRefPtr, uint32_t),
              (override));
  MOCK_METHOD(
      HotspotDeviceRefPtr,
      CreateHotspotDevice,
      (const std::string&, WiFiBand, WiFiSecurity, LocalDevice::EventCallback),
      (override));
  MOCK_METHOD(void, DeleteLocalDevice, (LocalDeviceRefPtr), (override));
  MOCK_METHOD(void, UpdateRegAndPhyInfo, (base::OnceClosure), (override));
  MOCK_METHOD(void, SetRegDomain, (RegulatorySource), (override));
  MOCK_METHOD(void, ResetRegDomain, (), (override));
  MOCK_METHOD(void, RegionChanged, (const std::string&), (override));
};

}  // namespace shill

#endif  // SHILL_WIFI_MOCK_WIFI_PROVIDER_H_
