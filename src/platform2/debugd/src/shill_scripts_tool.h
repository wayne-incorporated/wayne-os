// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_SHILL_SCRIPTS_TOOL_H_
#define DEBUGD_SRC_SHILL_SCRIPTS_TOOL_H_

#include <string>
#include <vector>

#include <base/files/scoped_file.h>
#include <brillo/errors/error.h>

#include "debugd/src/subprocess_tool.h"

namespace debugd {

class ShillScriptsTool : public SubprocessTool {
 public:
  ShillScriptsTool() = default;
  ShillScriptsTool(const ShillScriptsTool&) = delete;
  ShillScriptsTool& operator=(const ShillScriptsTool&) = delete;

  ~ShillScriptsTool() override = default;

  bool Run(const base::ScopedFD& outfd,
           const std::string& script,
           const std::vector<std::string>& script_args,
           std::string* out_id,
           brillo::ErrorPtr* error);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_SHILL_SCRIPTS_TOOL_H_
