// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/logging.h>
#include <base/strings/string_util.h>

#include "init/usermode-helper.h"

namespace usermode_helper {

namespace {

bool IsTestCaseFlag(const char* arg) {
  return std::string_view(arg) == "--core2md_failure" ||
         std::string_view(arg) == "--directory_failure";
}

// Processes core dumps from the kernel when a crash is detected.
// Controlled via /proc/sys/kernel/core_pattern.
bool ValidateCrashReporter(int argc, const char* argv[]) {
  // Allow normal crash reporting.  Most invocations will be this.
  if (argc == 2 &&
      base::StartsWith(argv[1], "--user=", base::CompareCase::SENSITIVE)) {
    return true;
  }

  // Allow early crash reporting invocation.
  if (argc == 4 && std::string_view(argv[1]) == "--early" &&
      std::string_view(argv[2]) == "--log_to_stderr" &&
      base::StartsWith(argv[3], "--user=", base::CompareCase::SENSITIVE)) {
    return true;
  }

  // Allow for crash-reporter crash testing invocations.
  if (argc == 3 &&
      base::StartsWith(argv[1], "--user=", base::CompareCase::SENSITIVE) &&
      std::string_view(argv[2]) == "--crash_test") {
    return true;
  }

  // Allow for log-collection-failure tests. Currently the test is being
  // transitioned from autotest to Tast, having 2 different versions.
  // TODO(crbug.com/1040335): Remove the former one after removing the
  // logging_UserCrash autotest.
  if (argc == 3 &&
      base::StartsWith(argv[1], "--user=", base::CompareCase::SENSITIVE) &&
      IsTestCaseFlag(argv[2])) {
    return true;
  }

  // Disallow all other invocations.
  LOG(ERROR) << "crash_reporter: unknown invocation";
  return false;
}

// Automatic module loading when kernel code calls request_module().
// Controlled via /proc/sys/kernel/modprobe.
bool ValidateModprobe(int argc, const char* argv[]) {
  // The kernel has loaded modules with the form `modprobe -q -- modname` since
  // at least linux-2.6.12.  We'll enforce that until the kernel changes, but it
  // rarely does, so maybe it's fine to be lazy.
  if (argc != 4) {
    LOG(ERROR) << "modprobe: argc must be 4";
    return false;
  }

  if (strcmp(argv[1], "-q") != 0) {
    LOG(ERROR) << "modprobe: argv[1] must be -q";
    return false;
  }

  if (strcmp(argv[2], "--") != 0) {
    LOG(ERROR) << "modprobe: argv[2] must be --";
    return false;
  }

  // We allow the last arg to be anything since the -- marker told modprobe to
  // parse it exactly as a module name and not an option.

  return true;
}

// When kernel code poweroffs the system by calling orderly_poweroff().
// This is not related to userspace calling `poweroff` or uses the reboot
// syscall.
// Controlled via /proc/sys/kernel/poweroff_cmd.
bool ValidatePoweroff(int argc, const char* argv[]) {
  if (argc != 1) {
    LOG(ERROR) << "poweroff: argc must be 1";
    return false;
  }

  return true;
}

// When kernel code reboots the system by calling orderly_reboot().
// This is not related to userspace calling `reboot` or uses the reboot
// syscall.
bool ValidateReboot(int argc, const char* argv[]) {
  if (argc != 1) {
    LOG(ERROR) << "reboot: argc must be 1";
    return false;
  }

  return true;
}

// When the kernel needs access to a key as part of the kernel keyring.
bool ValidateRequestKey(int argc, const char* argv[]) {
  // The kernel always executes this as:
  // /sbin/request-key <op> <key> <uid> <gid> <keyring> <keyring> <keyring>
  if (argc != 8) {
    LOG(ERROR) << "request-key: argc must be 8";
    return false;
  }

  // Don't allow any command line options.
  for (size_t i = 1; i < argc; ++i) {
    const std::string_view arg(argv[i]);
    if (arg[0] == '-') {
      LOG(ERROR) << "request-key: options not allowed: " << arg;
      return false;
    }
  }

  return true;
}

bool ValidateBridgeStp(int argc, const char* argv[]) {
  if (argc != 3) {
    LOG(ERROR) << "bridge-stp: argc must be 3";
    return false;
  }

  if (strcmp(argv[2], "start") != 0 && strcmp(argv[2], "stop") != 0) {
    LOG(ERROR) << "bridge-stp: argv[2] must be start or stop";
    return false;
  }

  return true;
}

}  // namespace

// Whether the arguments to the program are permitted.
bool ValidateProgramArgs(int argc, const char* argv[]) {
  const std::string_view prog(argv[0]);

  if (prog == "/sbin/crash_reporter")
    return ValidateCrashReporter(argc, argv);
  else if (prog == "/sbin/modprobe")
    return ValidateModprobe(argc, argv);
  else if (prog == "/sbin/poweroff")
    return ValidatePoweroff(argc, argv);
  else if (prog == "/sbin/reboot")
    return ValidateReboot(argc, argv);
  else if (prog == "/sbin/request-key")
    return ValidateRequestKey(argc, argv);
  else if (prog == "/sbin/bridge-stp")
    return ValidateBridgeStp(argc, argv);

  LOG(ERROR) << "program not permitted: " << argv[0];
  return false;
}

}  // namespace usermode_helper
