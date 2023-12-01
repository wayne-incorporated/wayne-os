// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTOHOME_MOCK_FIRMWARE_MANAGEMENT_PARAMETERS_H_
#define CRYPTOHOME_MOCK_FIRMWARE_MANAGEMENT_PARAMETERS_H_

#include "cryptohome/firmware_management_parameters.h"
#include <gmock/gmock.h>

namespace cryptohome {
class MockFirmwareManagementParameters : public FirmwareManagementParameters {
 public:
  MockFirmwareManagementParameters();
  virtual ~MockFirmwareManagementParameters();

  MOCK_METHOD(bool, Create, (), (override));
  MOCK_METHOD(bool, Destroy, (), (override));
  MOCK_METHOD(bool, Load, (), (override));
  MOCK_METHOD(bool, Store, (uint32_t, const brillo::Blob*), (override));
  MOCK_METHOD(bool, GetFlags, (uint32_t*), (override));
  MOCK_METHOD(bool, GetDeveloperKeyHash, (brillo::Blob*), (override));
  MOCK_METHOD(bool, IsLoaded, (), (const, override));
};
}  // namespace cryptohome

#endif  // CRYPTOHOME_MOCK_FIRMWARE_MANAGEMENT_PARAMETERS_H_
