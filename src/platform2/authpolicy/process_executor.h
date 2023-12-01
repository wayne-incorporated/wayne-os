// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef AUTHPOLICY_PROCESS_EXECUTOR_H_
#define AUTHPOLICY_PROCESS_EXECUTOR_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

struct minijail;

namespace authpolicy {

class Anonymizer;

// Helper class to execute commands and piping data. Uses minijail.
class ProcessExecutor {
 public:
  explicit ProcessExecutor(std::vector<std::string> args);
  ProcessExecutor(const ProcessExecutor&) = delete;
  ProcessExecutor& operator=(const ProcessExecutor&) = delete;

  // Gets the arguments passed into the constructor.
  const std::vector<std::string>& GetArgs() const { return args_; }

  // Adds a single argument to the end of the argument list.
  void PushArg(std::string arg) { args_.push_back(std::move(arg)); }

  // Set a file descriptor that gets piped into stdin during execution.
  // The file descriptor must stay valid until |Execute| is called.
  void SetInputFile(int fd);

  // Set a string that gets written to stdin during execution. If a file
  // descriptor is set as well, this string is appended to its data.
  void SetInputString(const std::string& input_str);

  // Set an environment variable '|key|=|value|, which is passed into the
  // process to be executed. Any number of variables can be set.
  void SetEnv(const std::string& key, const std::string& value);

  // Sets a seccomp filter by parsing the given file.
  void SetSeccompFilter(const std::string& policy_file);

  // Toggles logging of syscalls blocked by seccomp filters.
  void LogSeccompFilterFailures(bool enabled);

  // Toggles a flag that prevents execve from gaining new privileges.
  void SetNoNewPrivs(bool enabled);

  // Toggles a flag that prevents that supplementary groups are wiped.
  void KeepSupplementaryGroups(bool enabled);

  // Toggles logging of command line and the exit code.
  void LogCommand(bool enabled);

  // Toggles logging of the command output.
  void LogOutput(bool enabled);

  // Toggles logging of the command output if the command failed.
  void LogOutputOnError(bool enabled);

  // Sets the anonymizer to be applied to command logs.
  void SetAnonymizer(Anonymizer* anonymizer);

  // Execute the command. Returns true if the command executed and returned with
  // exit code 0. Also returns true if no args were passed to the constructor.
  // Returns false otherwise.
  // Calling |Execute| multiple times is possible. Note, however, that you might
  // have to call |SetInputFile| again if the input pipe was fully read.
  // Getters should only be called after execution.
  bool Execute();

  // On first call, if any type of logging is enabled, logs stdout and stderr
  // from the last call to Execute(). Subsequent calls do nothing. Called
  // automatically by Execute() if certain logging conditions are met. Call this
  // function if logging-on-error is enabled, the return code was 0, but you
  // want to log anyway, e.g. since the data was bad or unexpected.
  void LogOutputOnce();

  // When set to true, will perform IO on the child process' stdin, stdout and
  // stderr only after the child process has exited. Intended to allow testing
  // of the handling of error conditions.
  void SetPerformPipeIoAfterProcessExitForTesting(
      bool perform_pipe_io_after_process_exit_for_testing);

  // Populated after execute call.
  const std::string& GetStdout() const { return out_data_; }
  const std::string& GetStderr() const { return err_data_; }
  int GetExitCode() const { return exit_code_; }

  // GetExitCode() returns this if some internal error in Execute() occurred,
  // e.g. failed to copy stdin pipes. Not an actual return code from execve.
  static const int kExitCodeInternalError = 127;

 private:
  // Resets the output variables that are populated by |Execute|.
  void ResetOutput();

  // Logs stderr and stdout from the last command, if output logs are enabled.
  void MaybeLogOutput();

  std::vector<std::string> args_;
  std::map<std::string, std::string> env_map_;
  int input_fd_ = -1;
  std::string input_str_;
  std::string out_data_;
  std::string err_data_;
  int exit_code_ = 0;
  std::string seccomp_policy_file_;
  bool log_seccomp_failures_ = false;
  bool no_new_privs_ = false;
  bool keep_supplementary_flags_ = false;
  bool log_command_ = false;
  bool log_output_ = false;
  bool log_output_on_error_ = false;
  Anonymizer* anonymizer_ = nullptr;
  bool output_logged_ = false;
  bool perform_pipe_io_after_process_exit_for_testing_ = false;

  // We better not copy/assign because of |input_fd_|.
};

}  // namespace authpolicy

#endif  // AUTHPOLICY_PROCESS_EXECUTOR_H_
