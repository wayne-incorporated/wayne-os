// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_MOCK_ETHERNET_PROVIDER_H_
#define SHILL_ETHERNET_MOCK_ETHERNET_PROVIDER_H_

#include "shill/ethernet/ethernet_provider.h"

#include <gmock/gmock.h>

#include "shill/ethernet/ethernet_service.h"

namespace shill {

class MockEthernetProvider : public EthernetProvider {
 public:
  MockEthernetProvider();
  MockEthernetProvider(const MockEthernetProvider&) = delete;
  MockEthernetProvider& operator=(const MockEthernetProvider&) = delete;

  ~MockEthernetProvider() override;

  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(EthernetServiceRefPtr,
              CreateService,
              (base::WeakPtr<Ethernet>),
              (override));
  MOCK_METHOD(ServiceRefPtr,
              GetService,
              (const KeyValueStore& args, Error*),
              (override));
  MOCK_METHOD(void, RegisterService, (EthernetServiceRefPtr), (override));
  MOCK_METHOD(void, DeregisterService, (EthernetServiceRefPtr), (override));
  MOCK_METHOD(void, RefreshGenericEthernetService, (), (override));
};

}  // namespace shill

#endif  // SHILL_ETHERNET_MOCK_ETHERNET_PROVIDER_H_
