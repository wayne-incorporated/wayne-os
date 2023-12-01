// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_NETWORK_MANAGER_H_
#define MINIOS_MOCK_NETWORK_MANAGER_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "minios/network_manager_interface.h"

namespace minios {

class MockNetworkManagerObserver : public NetworkManagerInterface::Observer {
 public:
  MockNetworkManagerObserver() = default;

  MockNetworkManagerObserver(const MockNetworkManagerObserver&) = delete;
  MockNetworkManagerObserver& operator=(const MockNetworkManagerObserver&) =
      delete;

  MOCK_METHOD(void,
              OnConnect,
              (const std::string& ssid, brillo::Error* error),
              (override));

  MOCK_METHOD(
      void,
      OnGetNetworks,
      (const std::vector<NetworkManagerInterface::NetworkProperties>& networks,
       brillo::Error* error),
      (override));
};

class MockNetworkManager : public NetworkManagerInterface {
 public:
  MockNetworkManager() = default;

  MockNetworkManager(const MockNetworkManager&) = delete;
  MockNetworkManager& operator=(const MockNetworkManager&) = delete;

  MOCK_METHOD(void, AddObserver, (Observer * observer), (override));

  MOCK_METHOD(void, RemoveObserver, (Observer * observer), (override));

  MOCK_METHOD(void,
              Connect,
              (const std::string& ssid, const std::string& passphrase),
              (override));

  MOCK_METHOD(void, GetNetworks, (), (override));
};

}  // namespace minios

#endif  // MINIOS_MOCK_NETWORK_MANAGER_H_
