// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_MOCK_IPCONFIG_H_
#define SHILL_MOCK_IPCONFIG_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "shill/ipconfig.h"

namespace shill {

class MockIPConfig : public IPConfig {
 public:
  MockIPConfig(ControlInterface* control_interface,
               const std::string& device_name);
  MockIPConfig(const MockIPConfig&) = delete;
  MockIPConfig& operator=(const MockIPConfig&) = delete;

  ~MockIPConfig() override;

  MOCK_METHOD(const Properties&, properties, (), (const, override));
  MOCK_METHOD(void, ResetProperties, (), (override));
  MOCK_METHOD(void, EmitChanges, (), (override));
  MOCK_METHOD(void, UpdateDNSServers, (std::vector<std::string>), (override));

 private:
  const Properties& real_properties() const { return IPConfig::properties(); }
};

}  // namespace shill

#endif  // SHILL_MOCK_IPCONFIG_H_
