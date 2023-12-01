// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_ETHERNET_MOCK_ETHERNET_EAP_PROVIDER_H_
#define SHILL_ETHERNET_MOCK_ETHERNET_EAP_PROVIDER_H_

#include "shill/ethernet/ethernet_eap_provider.h"

#include <gmock/gmock.h>

#include "shill/ethernet/ethernet_eap_service.h"

namespace shill {

class MockEthernetEapProvider : public EthernetEapProvider {
 public:
  MockEthernetEapProvider();
  MockEthernetEapProvider(const MockEthernetEapProvider&) = delete;
  MockEthernetEapProvider& operator=(const MockEthernetEapProvider&) = delete;

  ~MockEthernetEapProvider() override;

  MOCK_METHOD(void, Start, (), (override));
  MOCK_METHOD(void, Stop, (), (override));
  MOCK_METHOD(void,
              SetCredentialChangeCallback,
              (Ethernet*, CredentialChangeCallback),
              (override));
  MOCK_METHOD(void, ClearCredentialChangeCallback, (Ethernet*), (override));
  MOCK_METHOD(void, OnCredentialsChanged, (), (const, override));
};

}  // namespace shill

#endif  // SHILL_ETHERNET_MOCK_ETHERNET_EAP_PROVIDER_H_
