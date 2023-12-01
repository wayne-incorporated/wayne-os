// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RMAD_UTILS_CMD_UTILS_H_
#define RMAD_UTILS_CMD_UTILS_H_

#include <string>
#include <vector>

namespace rmad {

// A wrapper for base::GetAppOutput and base::GetAppOutputAndError functions.
class CmdUtils {
 public:
  CmdUtils() = default;
  virtual ~CmdUtils() = default;

  virtual bool GetOutput(const std::vector<std::string>& argv,
                         std::string* output) const = 0;
  virtual bool GetOutputAndError(const std::vector<std::string>& argv,
                                 std::string* output) const = 0;
};

}  // namespace rmad

#endif  // RMAD_UTILS_CMD_UTILS_H_
