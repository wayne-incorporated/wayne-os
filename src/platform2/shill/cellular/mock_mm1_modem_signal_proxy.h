// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MM1_MODEM_SIGNAL_PROXY_H_
#define SHILL_CELLULAR_MOCK_MM1_MODEM_SIGNAL_PROXY_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/cellular/mm1_modem_signal_proxy_interface.h"

namespace shill {
namespace mm1 {

class MockModemSignalProxy : public ModemSignalProxyInterface {
 public:
  MockModemSignalProxy();
  MockModemSignalProxy(const MockModemSignalProxy&) = delete;
  MockModemSignalProxy& operator=(const MockModemSignalProxy&) = delete;

  ~MockModemSignalProxy() override;

  MOCK_METHOD(void,
              Setup,
              (const int, Error*, ResultCallback, int),
              (override));

  MOCK_METHOD(void,
              SetupThresholds,
              (const KeyValueStore& settings, Error*, ResultCallback, int),
              (override));
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MM1_MODEM_SIGNAL_PROXY_H_
