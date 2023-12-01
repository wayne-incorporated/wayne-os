// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_EC_UTILS_H_
#define RMAD_UTILS_MOCK_EC_UTILS_H_

#include "rmad/utils/ec_utils.h"

#include <gmock/gmock.h>

namespace rmad {

class MockEcUtils : public EcUtils {
 public:
  MockEcUtils() = default;
  ~MockEcUtils() override = default;

  MOCK_METHOD(bool, Reboot, (), (override));
  MOCK_METHOD(bool, GetEcWriteProtectionStatus, (bool*), (override));
  MOCK_METHOD(bool, EnableEcSoftwareWriteProtection, (), (override));
  MOCK_METHOD(bool, DisableEcSoftwareWriteProtection, (), (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_EC_UTILS_H_
