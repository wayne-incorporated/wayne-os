// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_CROS_HEALTHD_TOOL_H_
#define DEBUGD_SRC_CROS_HEALTHD_TOOL_H_

#include <string>

#include <brillo/errors/error.h>

namespace debugd {

class CrosHealthdTool {
 public:
  CrosHealthdTool() = default;
  CrosHealthdTool(const CrosHealthdTool&) = delete;
  CrosHealthdTool& operator=(const CrosHealthdTool&) = delete;

  ~CrosHealthdTool() = default;

  bool CollectSmartBatteryMetric(brillo::ErrorPtr* error,
                                 const std::string& metric_name,
                                 std::string* output);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_CROS_HEALTHD_TOOL_H_
