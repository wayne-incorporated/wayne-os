// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/mock_ipconfig.h"

using testing::Invoke;

namespace shill {

MockIPConfig::MockIPConfig(ControlInterface* control_interface,
                           const std::string& device_name)
    : IPConfig(control_interface, device_name) {
  ON_CALL(*this, properties())
      .WillByDefault(Invoke(this, &MockIPConfig::real_properties));
}

MockIPConfig::~MockIPConfig() = default;

}  // namespace shill
