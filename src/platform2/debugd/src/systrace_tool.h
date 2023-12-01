// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_SYSTRACE_TOOL_H_
#define DEBUGD_SRC_SYSTRACE_TOOL_H_

#include <string>

#include <base/files/scoped_file.h>

#include "debugd/src/subprocess_tool.h"

namespace debugd {

class SystraceTool {
 public:
  SystraceTool() = default;
  SystraceTool(const SystraceTool&) = delete;
  SystraceTool& operator=(const SystraceTool&) = delete;

  ~SystraceTool() = default;

  std::string Start(const std::string& categories);
  void Stop(const base::ScopedFD& outfd);
  std::string Status();
};

}  // namespace debugd

#endif  // DEBUGD_SRC_SYSTRACE_TOOL_H_
