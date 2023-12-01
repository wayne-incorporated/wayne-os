// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_REGIONS_UTILS_H_
#define RMAD_UTILS_MOCK_REGIONS_UTILS_H_

#include "rmad/utils/regions_utils.h"

#include <string>
#include <vector>

#include <gmock/gmock.h>

namespace rmad {

class MockRegionsUtils : public RegionsUtils {
 public:
  MockRegionsUtils() = default;
  ~MockRegionsUtils() override = default;

  MOCK_METHOD(bool,
              GetRegionList,
              (std::vector<std::string>*),
              (const, override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_REGIONS_UTILS_H_
