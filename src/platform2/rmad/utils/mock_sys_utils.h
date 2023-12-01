// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_SYS_UTILS_H_
#define RMAD_UTILS_MOCK_SYS_UTILS_H_

#include "rmad/utils/sys_utils.h"

#include <gmock/gmock.h>

namespace rmad {

class MockSysUtils : public SysUtils {
 public:
  MockSysUtils() = default;
  ~MockSysUtils() override = default;

  MOCK_METHOD(bool, IsPowerSourcePresent, (), (const, override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_SYS_UTILS_H_
