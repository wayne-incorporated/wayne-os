// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/utils/cmd_utils_impl.h"

#include <string>
#include <vector>

#include <base/process/launch.h>

namespace rmad {

bool CmdUtilsImpl::GetOutput(const std::vector<std::string>& argv,
                             std::string* output) const {
  CHECK(output);
  return base::GetAppOutput(argv, output);
}

bool CmdUtilsImpl::GetOutputAndError(const std::vector<std::string>& argv,
                                     std::string* output) const {
  CHECK(output);
  return base::GetAppOutputAndError(argv, output);
}

}  // namespace rmad
