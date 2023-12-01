// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_CROSSYSTEM_UTILS_H_
#define RMAD_UTILS_MOCK_CROSSYSTEM_UTILS_H_

#include "rmad/utils/crossystem_utils.h"

#include <map>
#include <string>

#include <gmock/gmock.h>

namespace rmad {

class MockCrosSystemUtils : public CrosSystemUtils {
 public:
  MockCrosSystemUtils() = default;
  ~MockCrosSystemUtils() override = default;

  MOCK_METHOD(bool, SetInt, (const std::string&, int), (override));
  MOCK_METHOD(bool, GetInt, (const std::string&, int*), (const, override));
  MOCK_METHOD(bool,
              SetString,
              (const std::string&, const std::string&),
              (override));
  MOCK_METHOD(bool,
              GetString,
              (const std::string&, std::string*),
              (const, override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_CROSSYSTEM_UTILS_H_
