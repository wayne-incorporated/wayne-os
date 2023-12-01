// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/scheduler_configuration_tool.h"

#include "debugd/src/error_utils.h"
#include "debugd/src/helper_utils.h"
#include "debugd/src/process_with_output.h"
#include "debugd/src/sandboxed_process.h"

#include <string>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <brillo/errors/error_codes.h>
#include <build/build_config.h>
#include <build/buildflag.h>
#include <chromeos/dbus/service_constants.h>

namespace debugd {

namespace {

constexpr char kErrorPath[] =
    "org.chromium.debugd.SchedulerConfigurationPolicyError";

const char kConservativePolicy[] = "conservative";

const char kPerformancePolicy[] = "performance";

const char kCoreIsolationPolicy[] = "core-scheduling";

bool IsValidSchedulerPolicy(const std::string& policy) {
  return ((policy == kConservativePolicy) || (policy == kPerformancePolicy) ||
          (policy == kCoreIsolationPolicy));
}

constexpr bool IsX86_64() {
#if defined(__x86_64__)
  return true;
#else
  return false;
#endif
}

// Executes a helper process with the expectation that any message printed to
// stderr indicates a failure that should be passed back over D-Bus.
// Returns false if any errors launching the process occur. Returns true
// otherwise, and sets |exit_status| if it isn't null.
bool RunHelper(const std::string& command,
               const ProcessWithOutput::ArgList& arguments,
               std::string* stdout,
               int* exit_status,
               brillo::ErrorPtr* error) {
  std::string helper_path;
  if (!GetHelperPath(command, &helper_path)) {
    DEBUGD_ADD_ERROR(error, kErrorPath, "Path too long");
    return false;
  }

  // Note: This runs the helper as root and without a sandbox only because the
  // helper immediately drops privileges and enforces its own sandbox. debugd
  // should not be used to launch unsandboxed executables.
  std::string stderr;
  int result = ProcessWithOutput::RunProcess(
      helper_path, arguments, true /*requires_root*/,
      true /* disable_sandbox */, nullptr, stdout, &stderr, error);

  if (!stderr.empty()) {
    DEBUGD_ADD_ERROR(error, kErrorPath, stderr.c_str());
    return false;
  }

  if (exit_status)
    *exit_status = result;
  return true;
}

}  // namespace

bool SchedulerConfigurationTool::SetPolicy(const std::string& policy,
                                           bool lock_policy,
                                           brillo::ErrorPtr* error,
                                           uint32_t* num_cores_disabled) {
  *num_cores_disabled = 0;

  if (!IsX86_64()) {
    DEBUGD_ADD_ERROR(error, kErrorPath, "Invalid architecture");
    return false;
  }

  if (!IsValidSchedulerPolicy(policy)) {
    DEBUGD_ADD_ERROR(error, kErrorPath, "Invalid policy " + policy);
    return false;
  }
  bool is_policy_conservative = (policy == kConservativePolicy);

  if (policy_locked_conservative_) {
    if (is_policy_conservative)
      return true;

    DEBUGD_ADD_ERROR(error, kErrorPath, "Policy locked to conservative");
    return false;
  }

  if (lock_policy && !is_policy_conservative) {
    DEBUGD_ADD_ERROR(error, kErrorPath, "Can't lock performance policy");
    return false;
  }

  int exit_status;
  std::string stdout;
  bool result = RunHelper("scheduler_configuration_helper",
                          ProcessWithOutput::ArgList{"--policy=" + policy},
                          &stdout, &exit_status, error);

  bool status = base::StringToUint(stdout, num_cores_disabled) && result &&
                (exit_status == 0);
  if (!status) {
    DEBUGD_ADD_ERROR(error, kErrorPath,
                     "scheduler_configuration_helper failed: stdout=" + stdout);
  } else {
    // The |policy_locked_conservative_| flag will only be set, if a
    // "conservative" policy was successfully set when it was asked to be
    // locked..
    policy_locked_conservative_ = is_policy_conservative && lock_policy;
  }

  return status;
}

}  // namespace debugd
