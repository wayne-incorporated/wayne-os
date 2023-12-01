// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_MOCK_SUPPLICANT_NETWORK_PROXY_H_
#define SHILL_SUPPLICANT_MOCK_SUPPLICANT_NETWORK_PROXY_H_

#include <gmock/gmock.h>

#include "shill/store/key_value_store.h"
#include "shill/supplicant/supplicant_network_proxy_interface.h"

namespace shill {

class MockSupplicantNetworkProxy : public SupplicantNetworkProxyInterface {
 public:
  MockSupplicantNetworkProxy();
  MockSupplicantNetworkProxy(const MockSupplicantNetworkProxy&) = delete;
  MockSupplicantNetworkProxy& operator=(const MockSupplicantNetworkProxy&) =
      delete;

  ~MockSupplicantNetworkProxy() override;

  MOCK_METHOD(bool, SetEnabled, (bool), (override));
  MOCK_METHOD(bool, SetProperties, (const KeyValueStore&), (override));
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_MOCK_SUPPLICANT_NETWORK_PROXY_H_
