// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_FUTILITY_UTILS_H_
#define RMAD_UTILS_MOCK_FUTILITY_UTILS_H_

#include "rmad/utils/futility_utils.h"

#include <gmock/gmock.h>

namespace rmad {

class MockFutilityUtils : public FutilityUtils {
 public:
  MockFutilityUtils() = default;
  ~MockFutilityUtils() override = default;

  MOCK_METHOD(bool, GetApWriteProtectionStatus, (bool*), (override));
  MOCK_METHOD(bool, EnableApSoftwareWriteProtection, (), (override));
  MOCK_METHOD(bool, DisableApSoftwareWriteProtection, (), (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_FUTILITY_UTILS_H_
