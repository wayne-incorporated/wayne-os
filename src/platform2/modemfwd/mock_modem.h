// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MODEMFWD_MOCK_MODEM_H_
#define MODEMFWD_MOCK_MODEM_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <gmock/gmock.h>

#include "modemfwd/modem.h"

namespace modemfwd {

class MockModem : public Modem {
 public:
  MockModem() = default;
  ~MockModem() override = default;

  MOCK_METHOD(std::string, GetDeviceId, (), (const, override));
  MOCK_METHOD(std::string, GetEquipmentId, (), (const, override));
  MOCK_METHOD(std::string, GetCarrierId, (), (const, override));
  MOCK_METHOD(std::string, GetPrimaryPort, (), (const, override));
  MOCK_METHOD(int, GetHeartbeatFailures, (), (const, override));
  MOCK_METHOD(void, ResetHeartbeatFailures, (), (override));
  MOCK_METHOD(void, IncrementHeartbeatFailures, (), (override));
  MOCK_METHOD(std::string, GetMainFirmwareVersion, (), (const, override));
  MOCK_METHOD(std::string, GetOemFirmwareVersion, (), (const, override));
  MOCK_METHOD(std::string, GetCarrierFirmwareId, (), (const, override));
  MOCK_METHOD(std::string, GetCarrierFirmwareVersion, (), (const, override));
  MOCK_METHOD(std::string,
              GetAssocFirmwareVersion,
              (std::string),
              (const, override));

  MOCK_METHOD(bool, SetInhibited, (bool), (override));

  MOCK_METHOD(bool,
              FlashFirmwares,
              (const std::vector<FirmwareConfig>&),
              (override));
  MOCK_METHOD(bool,
              ClearAttachAPN,
              (const std::string& carrier_uuid),
              (override));
};

}  // namespace modemfwd

#endif  // MODEMFWD_MOCK_MODEM_H_
