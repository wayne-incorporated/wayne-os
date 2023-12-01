// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_UPSTART_MOCK_UPSTART_PROXY_H_
#define SHILL_UPSTART_MOCK_UPSTART_PROXY_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/upstart/upstart_proxy_interface.h"

namespace shill {

class MockUpstartProxy : public UpstartProxyInterface {
 public:
  MockUpstartProxy();
  MockUpstartProxy(const MockUpstartProxy&) = delete;
  MockUpstartProxy& operator=(const MockUpstartProxy&) = delete;

  ~MockUpstartProxy() override;

  MOCK_METHOD(void,
              EmitEvent,
              (const std::string&, const std::vector<std::string>&, bool),
              (override));
};

}  // namespace shill

#endif  // SHILL_UPSTART_MOCK_UPSTART_PROXY_H_
