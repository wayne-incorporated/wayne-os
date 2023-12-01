// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_WRITE_PROTECT_UTILS_H_
#define RMAD_UTILS_MOCK_WRITE_PROTECT_UTILS_H_

#include "rmad/utils/write_protect_utils.h"

#include <gmock/gmock.h>

namespace rmad {

class MockWriteProtectUtils : public WriteProtectUtils {
 public:
  MockWriteProtectUtils() = default;
  ~MockWriteProtectUtils() override = default;

  MOCK_METHOD(bool,
              GetHardwareWriteProtectionStatus,
              (bool*),
              (const, override));
  MOCK_METHOD(bool, GetApWriteProtectionStatus, (bool*), (const, override));
  MOCK_METHOD(bool, GetEcWriteProtectionStatus, (bool*), (const, override));
  MOCK_METHOD(bool, DisableSoftwareWriteProtection, (), (override));
  MOCK_METHOD(bool, EnableSoftwareWriteProtection, (), (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_WRITE_PROTECT_UTILS_H_
