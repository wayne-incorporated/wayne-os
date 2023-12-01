// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MM1_MODEM_MODEM3GPP_PROXY_H_
#define SHILL_CELLULAR_MOCK_MM1_MODEM_MODEM3GPP_PROXY_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/cellular/mm1_modem_modem3gpp_proxy_interface.h"

namespace shill {
namespace mm1 {

class MockModemModem3gppProxy : public ModemModem3gppProxyInterface {
 public:
  MockModemModem3gppProxy();
  MockModemModem3gppProxy(const MockModemModem3gppProxy&) = delete;
  MockModemModem3gppProxy& operator=(const MockModemModem3gppProxy&) = delete;

  ~MockModemModem3gppProxy() override;

  MOCK_METHOD(void, Register, (const std::string&, ResultCallback), (override));
  MOCK_METHOD(void, Scan, (KeyValueStoresCallback), (override));
  MOCK_METHOD(void,
              SetInitialEpsBearerSettings,
              (const KeyValueStore&, ResultCallback),
              (override));
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MM1_MODEM_MODEM3GPP_PROXY_H_
