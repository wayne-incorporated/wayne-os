// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_OOM_ADJ_TOOL_H_
#define DEBUGD_SRC_OOM_ADJ_TOOL_H_

#include <stdint.h>
#include <sys/types.h>

#include <map>
#include <string>

#include "debugd/src/subprocess_tool.h"

namespace debugd {

class OomAdjTool : public SubprocessTool {
 public:
  OomAdjTool() = default;
  OomAdjTool(const OomAdjTool&) = delete;
  OomAdjTool& operator=(const OomAdjTool&) = delete;

  ~OomAdjTool() override = default;

  std::string Set(const std::map<pid_t, int32_t>& scores);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_OOM_ADJ_TOOL_H_
