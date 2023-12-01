// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_FUNCTIONS_SHELL_H_
#define RUNTIME_PROBE_FUNCTIONS_SHELL_H_

#include <memory>
#include <string>

#include "runtime_probe/probe_function.h"
#include "runtime_probe/probe_function_argument.h"

#include <base/logging.h>

namespace runtime_probe {

class ShellFunction : public ProbeFunction {
  using ProbeFunction::ProbeFunction;

 public:
  // The identifier / function name of this probe function.
  //
  // It will be used for both parsing and logging.
  NAME_PROBE_FUNCTION("shell");

 private:
  // Override `EvalImpl` function, which should return a list of Value.
  DataType EvalImpl() const override {
    VLOG(1) << "command: " << command_;
    VLOG(1) << "split_line: " << split_line_;
    // TODO(stimim): implement this

    return DataType{};
  }

  // Declare function arguments
  PROBE_FUNCTION_ARG_DEF(std::string, command);
  PROBE_FUNCTION_ARG_DEF(std::string, key, (std::string{"shell_raw"}));
  PROBE_FUNCTION_ARG_DEF(bool, split_line, (false));
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_FUNCTIONS_SHELL_H_
