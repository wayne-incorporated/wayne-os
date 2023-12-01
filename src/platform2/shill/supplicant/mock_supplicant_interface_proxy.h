// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_MOCK_SUPPLICANT_INTERFACE_PROXY_H_
#define SHILL_SUPPLICANT_MOCK_SUPPLICANT_INTERFACE_PROXY_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/refptr_types.h"
#include "shill/supplicant/supplicant_interface_proxy_interface.h"

namespace shill {

class MockSupplicantInterfaceProxy : public SupplicantInterfaceProxyInterface {
 public:
  MockSupplicantInterfaceProxy();
  MockSupplicantInterfaceProxy(const MockSupplicantInterfaceProxy&) = delete;
  MockSupplicantInterfaceProxy& operator=(const MockSupplicantInterfaceProxy&) =
      delete;

  ~MockSupplicantInterfaceProxy() override;

  MOCK_METHOD(bool,
              AddNetwork,
              (const KeyValueStore&, RpcIdentifier*),
              (override));
  MOCK_METHOD(bool, EAPLogoff, (), (override));
  MOCK_METHOD(bool, EAPLogon, (), (override));
  MOCK_METHOD(bool, Disconnect, (), (override));
  MOCK_METHOD(bool, FlushBSS, (const uint32_t&), (override));
  MOCK_METHOD(bool,
              NetworkReply,
              (const RpcIdentifier&, const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool, Reassociate, (), (override));
  MOCK_METHOD(bool, Reattach, (), (override));
  MOCK_METHOD(bool, RemoveAllNetworks, (), (override));
  MOCK_METHOD(bool, RemoveNetwork, (const RpcIdentifier&), (override));
  MOCK_METHOD(bool, Roam, (const std::string&), (override));
  MOCK_METHOD(bool, Scan, (const KeyValueStore&), (override));
  MOCK_METHOD(bool, SelectNetwork, (const RpcIdentifier&), (override));
  MOCK_METHOD(bool, SetFastReauth, (bool), (override));
  MOCK_METHOD(bool, SetScanInterval, (int32_t), (override));
  MOCK_METHOD(bool, SetScan, (bool), (override));
  MOCK_METHOD(bool,
              EnableMacAddressRandomization,
              (const std::vector<unsigned char>&, bool),
              (override));
  MOCK_METHOD(bool, DisableMacAddressRandomization, (), (override));
  MOCK_METHOD(bool, GetCapabilities, (KeyValueStore*), (override));
  MOCK_METHOD(bool,
              AddCred,
              (const KeyValueStore&, RpcIdentifier* cred),
              (override));
  MOCK_METHOD(bool, RemoveCred, (const RpcIdentifier& cred), (override));
  MOCK_METHOD(bool, RemoveAllCreds, (), (override));
  MOCK_METHOD(bool, InterworkingSelect, (), (override));
  MOCK_METHOD(bool, SignalPoll, (KeyValueStore*), (override));
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_MOCK_SUPPLICANT_INTERFACE_PROXY_H_
