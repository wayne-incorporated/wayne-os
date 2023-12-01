// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_CBI_UTILS_H_
#define RMAD_UTILS_MOCK_CBI_UTILS_H_

#include "rmad/utils/cbi_utils.h"

#include <string>

#include <gmock/gmock.h>

namespace rmad {

class MockCbiUtils : public CbiUtils {
 public:
  MockCbiUtils() = default;
  ~MockCbiUtils() override = default;

  MOCK_METHOD(bool, GetSkuId, (uint64_t*), (const, override));
  MOCK_METHOD(bool, GetDramPartNum, (std::string*), (const, override));
  MOCK_METHOD(bool, GetSsfc, (uint32_t*), (const, override));
  MOCK_METHOD(bool, SetSkuId, (uint64_t), (override));
  MOCK_METHOD(bool, SetDramPartNum, (const std::string&), (override));
  MOCK_METHOD(bool, SetSsfc, (uint32_t), (override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_CBI_UTILS_H_
