// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_CROS_CONFIG_UTILS_H_
#define RMAD_UTILS_MOCK_CROS_CONFIG_UTILS_H_

#include "rmad/utils/cros_config_utils.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace rmad {

class MockCrosConfigUtils : public CrosConfigUtils {
 public:
  MockCrosConfigUtils() = default;
  ~MockCrosConfigUtils() override = default;

  MOCK_METHOD(bool, GetRmadConfig, (RmadConfig*), (const, override));
  MOCK_METHOD(bool, GetModelName, (std::string*), (const, override));
  MOCK_METHOD(bool, GetSkuId, (uint64_t*), (const, override));
  MOCK_METHOD(bool, GetCustomLabelTag, (std::string*), (const, override));
  MOCK_METHOD(bool, GetSkuIdList, (std::vector<uint64_t>*), (const override));
  MOCK_METHOD(bool,
              GetCustomLabelTagList,
              (std::vector<std::string>*),
              (const override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_CROS_CONFIG_UTILS_H_
