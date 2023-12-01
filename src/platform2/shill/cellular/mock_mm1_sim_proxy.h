// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_MM1_SIM_PROXY_H_
#define SHILL_CELLULAR_MOCK_MM1_SIM_PROXY_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/cellular/mm1_sim_proxy_interface.h"

namespace shill {
namespace mm1 {

class MockSimProxy : public SimProxyInterface {
 public:
  MockSimProxy();
  MockSimProxy(const MockSimProxy&) = delete;
  MockSimProxy& operator=(const MockSimProxy&) = delete;

  ~MockSimProxy() override;

  MOCK_METHOD(void, SendPin, (const std::string&, ResultCallback), (override));
  MOCK_METHOD(void,
              SendPuk,
              (const std::string&, const std::string&, ResultCallback),
              (override));
  MOCK_METHOD(void,
              EnablePin,
              (const std::string&, const bool, ResultCallback),
              (override));
  MOCK_METHOD(void,
              ChangePin,
              (const std::string&, const std::string&, ResultCallback),
              (override));
};

}  // namespace mm1
}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_MM1_SIM_PROXY_H_
