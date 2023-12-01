// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_MOCK_ETHERNET_SERVICE_H_
#define SHILL_ETHERNET_MOCK_ETHERNET_SERVICE_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/ethernet/ethernet_service.h"
#include "shill/service.h"

namespace shill {

class MockEthernetService : public EthernetService {
 public:
  MockEthernetService(Manager* manager, base::WeakPtr<Ethernet> ethernet);
  MockEthernetService(const MockEthernetService&) = delete;
  MockEthernetService& operator=(const MockEthernetService&) = delete;

  ~MockEthernetService() override;

  MOCK_METHOD(void, Configure, (const KeyValueStore&, Error*), (override));
  MOCK_METHOD(void, Disconnect, (Error*, const char*), (override));
  MOCK_METHOD(RpcIdentifier, GetDeviceRpcId, (Error*), (const, override));
  MOCK_METHOD(std::string, GetStorageIdentifier, (), (const, override));
  MOCK_METHOD(bool, IsConnected, (Error*), (const, override));
  MOCK_METHOD(bool, IsConnecting, (), (const, override));
  MOCK_METHOD(bool, IsRemembered, (), (const, override));
  MOCK_METHOD(void, SetFailure, (ConnectFailure), (override));
  MOCK_METHOD(void, SetFailureSilent, (ConnectFailure), (override));
  MOCK_METHOD(void, SetState, (ConnectState), (override));
  MOCK_METHOD(void, OnVisibilityChanged, (), (override));
  MOCK_METHOD(Technology, technology, (), (const, override));
  MOCK_METHOD(bool, Is8021xConnectable, (), (const, override));
  MOCK_METHOD(bool,
              AddEAPCertification,
              (const std::string&, size_t),
              (override));
  MOCK_METHOD(void, ClearEAPCertification, (), (override));
  MOCK_METHOD(void,
              SetUplinkSpeedKbps,
              (uint32_t uplink_speed_kbps),
              (override));
  MOCK_METHOD(void,
              SetDownlinkSpeedKbps,
              (uint32_t downlink_speed_kbps),
              (override));
  MOCK_METHOD(ConnectState, state, (), (const, override));
  MOCK_METHOD(bool, IsPortalDetectionDisabled, (), (const, override));
};

}  // namespace shill

#endif  // SHILL_ETHERNET_MOCK_ETHERNET_SERVICE_H_
