// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_SYSRQ_TOOL_H_
#define DEBUGD_SRC_SYSRQ_TOOL_H_

#include <brillo/errors/error.h>

namespace debugd {

class SysrqTool {
 public:
  SysrqTool() = default;
  SysrqTool(const SysrqTool&) = delete;
  SysrqTool& operator=(const SysrqTool&) = delete;

  ~SysrqTool() = default;

  bool LogKernelTaskStates(brillo::ErrorPtr* error);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_SYSRQ_TOOL_H_
