// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MM1_MODEM_MODEM3GPP_PROFILE_MANAGER_PROXY_H_
#define SHILL_CELLULAR_MOCK_MM1_MODEM_MODEM3GPP_PROFILE_MANAGER_PROXY_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/cellular/mm1_modem_modem3gpp_profile_manager_proxy_interface.h"

namespace shill {
namespace mm1 {

class MockModemModem3gppProfileManagerProxy
    : public ModemModem3gppProfileManagerProxyInterface {
 public:
  MockModemModem3gppProfileManagerProxy();
  MockModemModem3gppProfileManagerProxy(
      const MockModemModem3gppProfileManagerProxy&) = delete;
  MockModemModem3gppProfileManagerProxy& operator=(
      const MockModemModem3gppProfileManagerProxy&) = delete;

  ~MockModemModem3gppProfileManagerProxy() override;

  // Inherited methods from ModemModem3gppProfileManagerProxyInterface.
  MOCK_METHOD(void,
              List,
              (ResultVariantDictionariesOnceCallback, int),
              (override));
  MOCK_METHOD(void,
              SetUpdatedCallback,
              (const Modem3gppProfileManagerUpdatedSignalCallback&),
              (override));
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MM1_MODEM_MODEM3GPP_PROFILE_MANAGER_PROXY_H_
