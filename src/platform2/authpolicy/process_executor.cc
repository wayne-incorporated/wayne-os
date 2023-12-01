// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "authpolicy/process_executor.h"

#include <stdlib.h>
#include <algorithm>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/stringprintf.h>
#include <libminijail.h>
#include <scoped_minijail.h>

#include "authpolicy/anonymizer.h"
#include "authpolicy/log_colors.h"
#include "authpolicy/platform_helper.h"
#include "authpolicy/samba_helper.h"

namespace authpolicy {
namespace {

// Prevent some environment variables from being wiped since they're used by
// tests. crbug.com/718182.
struct EnvVarDef {
  const char* name_equals;  // "name="
  size_t size;              // strlen("name=")
};

// Note: strlen doesn't work with constexpr.
#define DEFINE_ENV_VAR(name) \
  { name "=", sizeof(name "=") - 1 }

constexpr EnvVarDef kAllowlistedEnvVars[]{
    DEFINE_ENV_VAR("ASAN_OPTIONS"),  DEFINE_ENV_VAR("LSAN_OPTIONS"),
    DEFINE_ENV_VAR("MSAN_OPTIONS"),  DEFINE_ENV_VAR("TSAN_OPTIONS"),
    DEFINE_ENV_VAR("UBSAN_OPTIONS"),
};

#undef DEFINE_ENV_VAR

}  // namespace

ProcessExecutor::ProcessExecutor(std::vector<std::string> args)
    : args_(std::move(args)) {}

void ProcessExecutor::SetInputFile(int fd) {
  input_fd_ = fd;
}

void ProcessExecutor::SetInputString(const std::string& input_str) {
  input_str_ = input_str;
}

void ProcessExecutor::SetEnv(const std::string& key, const std::string& value) {
  env_map_[key] = value;
}

void ProcessExecutor::SetSeccompFilter(const std::string& policy_file) {
  seccomp_policy_file_ = policy_file;
}

void ProcessExecutor::LogSeccompFilterFailures(bool enabled) {
  log_seccomp_failures_ = enabled;
}

void ProcessExecutor::SetNoNewPrivs(bool enabled) {
  no_new_privs_ = enabled;
}

void ProcessExecutor::KeepSupplementaryGroups(bool enabled) {
  keep_supplementary_flags_ = enabled;
}

void ProcessExecutor::LogCommand(bool enabled) {
  log_command_ = enabled;
}

void ProcessExecutor::LogOutput(bool enabled) {
  log_output_ = enabled;
}

void ProcessExecutor::LogOutputOnError(bool enabled) {
  log_output_on_error_ = enabled;
}

void ProcessExecutor::SetAnonymizer(Anonymizer* anonymizer) {
  anonymizer_ = anonymizer;
}

bool ProcessExecutor::Execute() {
  ResetOutput();
  if (args_.empty() || args_[0].empty())
    return true;

  bool need_anonymizer = log_command_ || log_output_ || log_output_on_error_;
  CHECK(anonymizer_ || !need_anonymizer) << "Logs must be anonymized";

  if (!base::FilePath(args_[0]).IsAbsolute()) {
    LOG(ERROR) << "Command must be specified by absolute path.";
    exit_code_ = kExitCodeInternalError;
    return false;
  }

  if (log_command_ && LOG_IS_ON(INFO)) {
    std::string cmd = args_[0];
    for (size_t n = 1; n < args_.size(); ++n)
      cmd += base::StringPrintf(" '%s'", args_[n].c_str());
    LOG(INFO) << kColorCommand << "Executing " << anonymizer_->Process(cmd)
              << kColorReset;
  }

  // Convert args to array of pointers. Must be nullptr terminated.
  std::vector<char*> args_ptr;
  for (const auto& arg : args_)
    args_ptr.push_back(const_cast<char*>(arg.c_str()));
  args_ptr.push_back(nullptr);

  // Save old environment and set ours. Note that clearenv() doesn't actually
  // delete any pointers, so we can just keep the old pointers.
  std::vector<char*> old_environ;
  for (char** env = environ; env != nullptr && *env != nullptr; ++env)
    old_environ.push_back(*env);
  clearenv();

  // Store strings in list because putenv requires pointers to stay alive.
  std::vector<std::string> env_list;
  for (const auto& env : env_map_) {
    env_list.push_back(env.first + "=" + env.second);
    putenv(const_cast<char*>(env_list.back().c_str()));
  }

  // Add back allowlisted env vars. Note that |allowlisted_var.name_equals| is
  // name= and |env| is name=value. A linear search seems fine, but consider
  // using a map if kAllowlistedEnvVars grows.
  for (char* env : old_environ) {
    for (const EnvVarDef& allowlisted_var : kAllowlistedEnvVars) {
      if (strncmp(env, allowlisted_var.name_equals, allowlisted_var.size) == 0)
        putenv(env);
    }
  }

  // Prepare minijail.
  ScopedMinijail jail(minijail_new());
  if (log_seccomp_failures_)
    minijail_log_seccomp_filter_failures(jail.get());
  if (!seccomp_policy_file_.empty()) {
    minijail_parse_seccomp_filters(jail.get(), seccomp_policy_file_.c_str());
    minijail_use_seccomp_filter(jail.get());
  }
  if (no_new_privs_)
    minijail_no_new_privs(jail.get());
  if (keep_supplementary_flags_)
    minijail_keep_supplementary_gids(jail.get());

  // Execute the command.
  pid_t pid = -1;
  int child_stdin = -1, child_stdout = -1, child_stderr = -1;
  minijail_run_pid_pipes(jail.get(), args_ptr[0], args_ptr.data(), &pid,
                         &child_stdin, &child_stdout, &child_stderr);

  // Make sure the pipes never block.
  if (!base::SetNonBlocking(child_stdin))
    LOG(WARNING) << "Failed to set stdin non-blocking";
  if (!base::SetNonBlocking(child_stdout))
    LOG(WARNING) << "Failed to set stdout non-blocking";
  if (!base::SetNonBlocking(child_stderr))
    LOG(WARNING) << "Failed to set stderr non-blocking";

  // Restore the environment.
  clearenv();
  for (char* env : old_environ)
    putenv(env);

  if (perform_pipe_io_after_process_exit_for_testing_)
    exit_code_ = minijail_wait(jail.get());

  // Write to child_stdin and read from child_stdout and child_stderr while
  // there is still data to read/write.
  bool io_success =
      PerformPipeIo(child_stdin, child_stdout, child_stderr, input_fd_,
                    input_str_, &out_data_, &err_data_);

  // Wait for the process to exit.
  if (!perform_pipe_io_after_process_exit_for_testing_)
    exit_code_ = minijail_wait(jail.get());
  jail.reset();

  // Print out a useful error message for seccomp failures.
  if (exit_code_ == MINIJAIL_ERR_JAIL)
    LOG(ERROR) << "Seccomp filter blocked a system call";

  // Always exit AFTER minijail_wait! If we do it before, the exit code is never
  // queried and the process is left dangling.
  if (!io_success) {
    LOG(ERROR) << "IO failed";
    exit_code_ = kExitCodeInternalError;
    return false;
  }

  output_logged_ = false;
  if (log_output_ || (log_output_on_error_ && exit_code_ != 0))
    LogOutputOnce();
  LOG_IF(INFO, log_command_)
      << kColorCommand << "Exit code: " << exit_code_ << kColorReset;

  return exit_code_ == 0;
}

void ProcessExecutor::LogOutputOnce() {
  if (output_logged_ || args_.empty() || !(log_output_on_error_ || log_output_))
    return;
  LogLongString(kColorCommandStdout, args_[0] + " stdout: ", out_data_,
                anonymizer_);
  LogLongString(kColorCommandStderr, args_[0] + " stderr: ", err_data_,
                anonymizer_);
  output_logged_ = true;
}

void ProcessExecutor::SetPerformPipeIoAfterProcessExitForTesting(
    bool perform_pipe_io_after_process_exit_for_testing) {
  perform_pipe_io_after_process_exit_for_testing_ =
      perform_pipe_io_after_process_exit_for_testing;
}

void ProcessExecutor::ResetOutput() {
  exit_code_ = 0;
  out_data_.clear();
  err_data_.clear();
}

}  // namespace authpolicy
