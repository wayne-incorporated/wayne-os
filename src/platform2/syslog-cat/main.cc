// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/process/process.h>
#include <base/strings/string_util.h>

#include <brillo/flag_helper.h>

#include "syslog-cat/syslogcat.h"

namespace {
constexpr char kDefaultSeverityStdout[] = "info";
constexpr char kDefaultSeverityStderr[] = "warn";
constexpr char kSyslogSocketPath[] = "/run/rsyslogd/stdout";

int SeverityFromString(const base::StringPiece& severity) {
  std::string severity_lower = base::ToLowerASCII(severity);
  if (severity_lower == "0" || severity_lower == "emerg") {
    return 0;
  }

  if (severity_lower == "1" || severity_lower == "alert") {
    return 1;
  }

  if (severity_lower == "2" || severity_lower == "critical" ||
      severity_lower == "crit") {
    return 2;
  }

  if (severity_lower == "3" || severity_lower == "err" ||
      severity_lower == "error") {
    return 3;
  }

  if (severity_lower == "4" || severity_lower == "warn" ||
      severity_lower == "warning") {
    return 4;
  }

  if (severity_lower == "5" || severity_lower == "notice") {
    return 5;
  }

  if (severity_lower == "6" || severity_lower == "info") {
    return 6;
  }

  if (severity_lower == "7" || severity_lower == "debug") {
    return 7;
  }

  return -1;
}

}  // namespace

int main(int argc, char* argv[]) {
  DEFINE_string(identifier, "", "Identifier string of syslog");
  DEFINE_string(severity_stdout, kDefaultSeverityStdout,
                "Severity value which is used in sendin stdout to syslog");
  DEFINE_string(severity_stderr, kDefaultSeverityStderr,
                "Severity value which is used in sendin stderr to syslog");

  brillo::FlagHelper::Init(
      argc, argv,
      "Captures the stdout/stderr of the specified program and forward them "
      "to syslog.");

  const auto& sv = base::CommandLine::ForCurrentProcess()->GetArgs();
  if (sv.size() == 0) {
    LOG(ERROR) << "Syslog-cat requres the command line to execute.";
    return 1;
  }

  const std::string& target_command = sv[0];

  // Prepare a identifier.
  std::string identifier = FLAGS_identifier;
  if (identifier.empty()) {
    // Fallback to the default.
    identifier = base::FilePath(target_command).BaseName().value();
  }
  if (identifier.empty()) {
    // Failed to fallback for some reason.
    LOG(ERROR) << "Failed to extract a identifier string.";
    return 1;
  }

  // Prepare a severity for stdout.
  int severity_stdout = SeverityFromString(FLAGS_severity_stdout);
  if (severity_stdout < 0) {
    LOG(ERROR) << "Invalid --severity_stdout value '" << severity_stdout
               << "'. It must be a number between 0 (EMERG) and 7 (DEBUG) or "
                  "valid severity string.";
    return 1;
  }

  // Prepare a severity for stderr.
  int severity_stderr = SeverityFromString(FLAGS_severity_stderr);
  if (severity_stderr < 0) {
    LOG(ERROR) << "Invalid --severity_stderr value '" << severity_stderr
               << "'. It must be a number between 0 (EMERG) and 7 (DEBUG) or "
                  "valid severity string.";
    return 1;
  }

  // Prepare a command line for the target process.
  int target_command_argc = sv.size();
  std::vector<const char*> target_command_argv(target_command_argc + 1);
  for (int i = 0; i < target_command_argc; i++)
    target_command_argv[i] = sv[i].c_str();
  target_command_argv[target_command_argc] = nullptr;

  ExecuteCommandWithRedirection(target_command, target_command_argv, identifier,
                                severity_stdout, severity_stderr,
                                base::FilePath(kSyslogSocketPath),
                                base::FilePath(kSyslogSocketPath));

  // The method above should never return unless an error happens.

  // Crashes itself by the FATAL error message.
  LOG(FATAL) << "Executing the command is unexpectedly failed.";
}
