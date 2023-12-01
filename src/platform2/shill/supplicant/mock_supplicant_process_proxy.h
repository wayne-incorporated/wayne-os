// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_SUPPLICANT_MOCK_SUPPLICANT_PROCESS_PROXY_H_
#define SHILL_SUPPLICANT_MOCK_SUPPLICANT_PROCESS_PROXY_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/supplicant/supplicant_process_proxy_interface.h"

namespace shill {

class MockSupplicantProcessProxy : public SupplicantProcessProxyInterface {
 public:
  MockSupplicantProcessProxy();
  MockSupplicantProcessProxy(const MockSupplicantProcessProxy&) = delete;
  MockSupplicantProcessProxy& operator=(const MockSupplicantProcessProxy&) =
      delete;

  ~MockSupplicantProcessProxy() override;

  MOCK_METHOD(bool,
              CreateInterface,
              (const KeyValueStore&, RpcIdentifier*),
              (override));
  MOCK_METHOD(bool,
              GetInterface,
              (const std::string&, RpcIdentifier*),
              (override));
  MOCK_METHOD(bool, RemoveInterface, (const RpcIdentifier&), (override));
  MOCK_METHOD(bool, GetDebugLevel, (std::string*), (override));
  MOCK_METHOD(bool, SetDebugLevel, (const std::string&), (override));
  MOCK_METHOD(bool, ExpectDisconnect, (), (override));
};

}  // namespace shill

#endif  // SHILL_SUPPLICANT_MOCK_SUPPLICANT_PROCESS_PROXY_H_
