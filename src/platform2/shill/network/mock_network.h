// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_NETWORK_MOCK_NETWORK_H_
#define SHILL_NETWORK_MOCK_NETWORK_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/functional/callback.h>
#include <base/time/time.h>
#include <chromeos/patchpanel/dbus/client.h>
#include <gmock/gmock.h>

#include "shill/ipconfig.h"
#include "shill/network/network.h"
#include "shill/network/network_priority.h"
#include "shill/portal_detector.h"
#include "shill/technology.h"

namespace shill {

// TODO(b/182777518): Consider a fake implementation after we finish refactoring
// the Network class interface.
class MockNetwork : public Network {
 public:
  explicit MockNetwork(int interface_index,
                       const std::string& interface_name,
                       Technology technology);
  MockNetwork(const MockNetwork&) = delete;
  MockNetwork& operator=(const MockNetwork&) = delete;
  ~MockNetwork() override;

  MOCK_METHOD(void, Start, (const StartOptions&), (override));
  MOCK_METHOD(void, Stop, (), (override));

  MOCK_METHOD(bool, IsConnected, (), (const, override));
  MOCK_METHOD(bool, HasInternetConnectivity, (), (const, override));

  MOCK_METHOD(void,
              set_link_protocol_ipv4_properties,
              (std::unique_ptr<IPConfig::Properties>),
              (override));

  MOCK_METHOD(void,
              OnStaticIPConfigChanged,
              (const NetworkConfig&),
              (override));
  MOCK_METHOD(void,
              RegisterCurrentIPConfigChangeHandler,
              (base::RepeatingClosure),
              (override));
  MOCK_METHOD(IPConfig*, GetCurrentIPConfig, (), (const, override));

  MOCK_METHOD(std::vector<IPAddress>, GetAddresses, (), (const, override));
  MOCK_METHOD(std::vector<IPAddress>, GetDNSServers, (), (const, override));

  MOCK_METHOD(bool, RenewDHCPLease, (), (override));
  MOCK_METHOD(void, DestroyDHCPLease, (const std::string&), (override));
  MOCK_METHOD(std::optional<base::TimeDelta>,
              TimeToNextDHCPLeaseRenewal,
              (),
              (override));

  MOCK_METHOD(void, InvalidateIPv6Config, (), (override));

  MOCK_METHOD(void, SetPriority, (NetworkPriority), (override));

  MOCK_METHOD(void,
              OnNeighborReachabilityEvent,
              (const patchpanel::Client::NeighborReachabilityEvent&));
  MOCK_METHOD(bool, ipv4_gateway_found, (), (const, override));
  MOCK_METHOD(bool, ipv6_gateway_found, (), (const, override));
  MOCK_METHOD(bool, StartPortalDetection, (bool), (override));
  MOCK_METHOD(bool, RestartPortalDetection, (), (override));
  MOCK_METHOD(void, StopPortalDetection, (), (override));
  MOCK_METHOD(bool, IsPortalDetectionInProgress, (), (const, override));
  MOCK_METHOD(void, StartConnectionDiagnostics, (), (override));
  MOCK_METHOD(bool, IsConnectedViaTether, (), (const, override));
  MOCK_METHOD(void,
              StartConnectivityTest,
              (PortalDetector::ProbingConfiguration probe_config),
              (override));
};

class MockNetworkEventHandler : public Network::EventHandler {
 public:
  MockNetworkEventHandler();
  MockNetworkEventHandler(const MockNetworkEventHandler&) = delete;
  MockNetworkEventHandler& operator=(const MockNetworkEventHandler&) = delete;
  ~MockNetworkEventHandler();

  MOCK_METHOD(void, OnConnectionUpdated, (int), (override));
  MOCK_METHOD(void, OnNetworkStopped, (int, bool), (override));
  MOCK_METHOD(void, OnIPConfigsPropertyUpdated, (int), (override));
  MOCK_METHOD(void, OnGetDHCPLease, (int), (override));
  MOCK_METHOD(void, OnGetDHCPFailure, (int), (override));
  MOCK_METHOD(void, OnGetSLAACAddress, (int), (override));
  MOCK_METHOD(void, OnIPv4ConfiguredWithDHCPLease, (int), (override));
  MOCK_METHOD(void, OnIPv6ConfiguredWithSLAACAddress, (int), (override));
  MOCK_METHOD(void,
              OnNeighborReachabilityEvent,
              (int,
               const IPAddress&,
               patchpanel::Client::NeighborRole,
               patchpanel::Client::NeighborStatus));
  MOCK_METHOD(void, OnNetworkValidationStart, (int), (override));
  MOCK_METHOD(void, OnNetworkValidationStop, (int), (override));
  MOCK_METHOD(void,
              OnNetworkValidationResult,
              (int, const PortalDetector::Result& result),
              (override));
  MOCK_METHOD(void, OnNetworkDestroyed, (int), (override));
};

}  // namespace shill

#endif  // SHILL_NETWORK_MOCK_NETWORK_H_
