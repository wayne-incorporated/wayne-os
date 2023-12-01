// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_MOCK_CMD_UTILS_H_
#define RMAD_UTILS_MOCK_CMD_UTILS_H_

#include "rmad/utils/cmd_utils.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"

namespace rmad {

class MockCmdUtils : public CmdUtils {
 public:
  MockCmdUtils() = default;
  ~MockCmdUtils() override = default;

  MOCK_METHOD(bool,
              GetOutput,
              (const std::vector<std::string>&, std::string*),
              (const, override));
  MOCK_METHOD(bool,
              GetOutputAndError,
              (const std::vector<std::string>&, std::string*),
              (const, override));
};

}  // namespace rmad

#endif  // RMAD_UTILS_MOCK_CMD_UTILS_H_
