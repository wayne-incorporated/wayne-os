// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TYPECD_MOCK_PORT_H_
#define TYPECD_MOCK_PORT_H_

#include <string>

#include <gmock/gmock.h>

#include "typecd/port.h"

namespace typecd {

// A mock implementation of the Port class which can be used to test various
// scenarios of PortManager::RunModeEntry().
class MockPort : public Port {
 public:
  MockPort(base::FilePath path, int port_num) : Port(path, port_num) {}

  MOCK_METHOD(DataRole, GetDataRole, (), (override));
  MOCK_METHOD(PowerRole, GetPowerRole, (), (override));
  MOCK_METHOD(Panel, GetPanel, (), (override));
  MOCK_METHOD(bool,
              CanEnterDPAltMode,
              (bool* invalid_dpalt_cable_ptr),
              (override));
  MOCK_METHOD(ModeEntryResult, CanEnterTBTCompatibilityMode, (), (override));
  MOCK_METHOD(ModeEntryResult, CanEnterUSB4, (), (override));
  MOCK_METHOD(bool, IsPartnerDiscoveryComplete, (), (override));
  MOCK_METHOD(bool, IsCableDiscoveryComplete, (), (override));
  MOCK_METHOD(bool, CableLimitingUSBSpeed, (bool), (override));
  MOCK_METHOD(void, ReportMetrics, (Metrics*, bool), ());
  MOCK_METHOD(void, AddRemovePartnerPowerProfile, (bool), (override));
};

}  // namespace typecd

#endif  // TYPECD_MOCK_PORT_H_
