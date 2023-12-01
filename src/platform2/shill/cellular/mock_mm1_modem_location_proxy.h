// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MM1_MODEM_LOCATION_PROXY_H_
#define SHILL_CELLULAR_MOCK_MM1_MODEM_LOCATION_PROXY_H_

#include <gmock/gmock.h>

#include "shill/cellular/mm1_modem_location_proxy_interface.h"

namespace shill {
namespace mm1 {

class MockModemLocationProxy : public ModemLocationProxyInterface {
 public:
  MockModemLocationProxy();
  MockModemLocationProxy(const MockModemLocationProxy&) = delete;
  MockModemLocationProxy& operator=(const MockModemLocationProxy&) = delete;

  ~MockModemLocationProxy() override;

  // Inherited methods from ModemLocationProxyInterface.
  MOCK_METHOD(void,
              Setup,
              (uint32_t, bool, Error*, ResultCallback, int),
              (override));
  MOCK_METHOD(void, GetLocation, (Error*, BrilloAnyCallback, int), (override));
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MM1_MODEM_LOCATION_PROXY_H_
