// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_PROBE_TOOL_H_
#define DEBUGD_SRC_PROBE_TOOL_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/values.h>
#include <brillo/errors/error.h>
#include <brillo/process/process.h>

namespace debugd {

class ProbeTool {
 public:
  ProbeTool() = default;
  ProbeTool(const ProbeTool&) = delete;
  ProbeTool& operator=(const ProbeTool&) = delete;

  virtual ~ProbeTool() = default;

  // Executes the function defined for runtime_probe.
  bool EvaluateProbeFunction(brillo::ErrorPtr* error,
                             const std::string& probe_statement,
                             int log_level,
                             base::ScopedFD* outfd,
                             base::ScopedFD* errfd);

  std::unique_ptr<brillo::Process> CreateSandboxedProcess(
      brillo::ErrorPtr* error, const std::string& probe_statement);

 protected:
  bool GetValidMinijailArguments(brillo::ErrorPtr* error,
                                 const std::string& probe_statement_str,
                                 std::string* function_name_out,
                                 std::string* user_out,
                                 std::string* group_out,
                                 std::vector<std::string>* args_out);

  virtual std::optional<base::Value::Dict> LoadMinijailArguments(
      brillo::ErrorPtr* error);

 private:
  std::vector<base::FilePath> FilesUnderPath(const std::string& root) const;

  std::optional<base::Value::Dict> minijail_args_dict_;
};

}  // namespace debugd

#endif  // DEBUGD_SRC_PROBE_TOOL_H_
