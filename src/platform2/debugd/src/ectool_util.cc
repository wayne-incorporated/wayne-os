// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/ectool_util.h"

#include <base/files/file_util.h>

#include "debugd/src/error_utils.h"
#include "debugd/src/process_with_output.h"

namespace {

constexpr char kErrorPath[] = "org.chromium.debugd.ECToolError";
constexpr char kEctoolBinary[] = "/usr/sbin/ectool";

}  // namespace

namespace debugd {

// Runs ectool with the provided |ectool_args| in a sandboxed process. Returns
// true on success.
bool RunEctoolWithArgs(brillo::ErrorPtr* error,
                       const base::FilePath& seccomp_policy_path,
                       const std::vector<std::string> ectool_args,
                       const std::string& user,
                       std::string* output) {
  if (!base::PathExists(seccomp_policy_path)) {
    DEBUGD_ADD_ERROR(error, kErrorPath,
                     "Sandbox info is missing for this architecture.");
    return false;
  }

  // Minijail setup for ectool.
  std::vector<std::string> parsed_args{"-c", "cap_sys_rawio=e", "-b",
                                       "/dev/cros_ec"};

  ProcessWithOutput process;
  process.SandboxAs(user, user);
  process.SetSeccompFilterPolicyFile(seccomp_policy_path.MaybeAsASCII());
  process.InheritUsergroups();
  if (!process.Init(parsed_args)) {
    DEBUGD_ADD_ERROR(error, kErrorPath, "Process initialization failure.");
    return false;
  }

  process.AddArg(kEctoolBinary);
  for (const auto& arg : ectool_args)
    process.AddArg(arg);
  if (process.Run() != EXIT_SUCCESS) {
    DEBUGD_ADD_ERROR(error, kErrorPath, "Failed to run process.");
    return false;
  }

  if (!process.GetOutput(output)) {
    DEBUGD_ADD_ERROR(error, kErrorPath, "Failed to get output from process.");
    return false;
  }

  return true;
}

}  // namespace debugd
