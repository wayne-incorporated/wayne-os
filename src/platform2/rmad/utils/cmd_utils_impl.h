// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_CMD_UTILS_IMPL_H_
#define RMAD_UTILS_CMD_UTILS_IMPL_H_

#include "rmad/utils/cmd_utils.h"

#include <string>
#include <vector>

namespace rmad {

class CmdUtilsImpl : public CmdUtils {
 public:
  CmdUtilsImpl() = default;
  ~CmdUtilsImpl() override = default;

  bool GetOutput(const std::vector<std::string>& argv,
                 std::string* output) const override;
  bool GetOutputAndError(const std::vector<std::string>& argv,
                         std::string* output) const override;
};

}  // namespace rmad

#endif  // RMAD_UTILS_CMD_UTILS_IMPL_H_
