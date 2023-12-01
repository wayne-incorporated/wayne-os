// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SHILL_CELLULAR_MOCK_CELLULAR_SERVICE_H_
#define SHILL_CELLULAR_MOCK_CELLULAR_SERVICE_H_

#include <string>

#include <gmock/gmock.h>

#include "shill/cellular/cellular_service.h"

namespace shill {

class MockCellularService : public CellularService {
 public:
  MockCellularService(Manager* manager, const CellularRefPtr& device);
  MockCellularService(const MockCellularService&) = delete;
  MockCellularService& operator=(const MockCellularService&) = delete;

  ~MockCellularService() override;

  MOCK_METHOD(void, AutoConnect, (), (override));
  MOCK_METHOD(void, SetLastGoodApn, (const Stringmap&), (override));
  MOCK_METHOD(void, ClearLastGoodApn, (), (override));
  MOCK_METHOD(void, SetActivationState, (const std::string&), (override));
  MOCK_METHOD(void, Connect, (Error*, const char*), (override));
  MOCK_METHOD(void, Disconnect, (Error*, const char*), (override));
  MOCK_METHOD(void, SetState, (ConnectState), (override));
  MOCK_METHOD(void, SetFailure, (ConnectFailure), (override));
  MOCK_METHOD(void, SetFailureSilent, (ConnectFailure), (override));
  MOCK_METHOD(void, SetStrength, (uint8_t), (override));
  MOCK_METHOD(ConnectState, state, (), (const, override));
  MOCK_METHOD(bool, explicitly_disconnected, (), (const, override));
  MOCK_METHOD(const std::string&, activation_state, (), (const, override));
  MOCK_METHOD(void,
              SetUplinkSpeedKbps,
              (uint32_t uplink_speed_kbps),
              (override));
  MOCK_METHOD(void,
              SetDownlinkSpeedKbps,
              (uint32_t downlink_speed_kbps),
              (override));

 private:
  std::string default_activation_state_;
};

}  // namespace shill

#endif  // SHILL_CELLULAR_MOCK_CELLULAR_SERVICE_H_
