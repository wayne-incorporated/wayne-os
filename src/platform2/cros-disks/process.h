// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CROS_DISKS_PROCESS_H_
#define CROS_DISKS_PROCESS_H_

#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <gtest/gtest_prod.h>

#include "cros-disks/sandboxed_init.h"

namespace cros_disks {

// A base class for executing and monitoring a process.
class Process {
 public:
  // Exit code of a process. Valid values are in the range from 0 to 255.
  enum class ExitCode : int {
    kNone = -1,
    kSuccess = 0,
    kMax = 255,
  };

  // Invalid process ID assigned to a process that has not started.
  static const pid_t kInvalidProcessId;

  Process(const Process&) = delete;
  Process& operator=(const Process&) = delete;

  virtual ~Process();

  // Adds an argument to the end of the argument list.
  // Precondition: Start() has not been called yet.
  void AddArgument(std::string argument);

  // Adds a variable to the environment that will be passed to the process.
  // Precondition: Start() has not been called yet.
  // Precondition: `name` is not empty and doesn't contain '='.
  void AddEnvironmentVariable(base::StringPiece name, base::StringPiece value);

  // Sets the string to pass to the process stdin.
  // Might be silently truncated if it doesn't fit in a pipe's buffer.
  // Precondition: Start() has not been called yet.
  void SetStdIn(std::string input) { input_ = std::move(input); }

  // Callback called when a line of message is captured from the process stdout
  // or stderr. The final linefeed character '\n' is stripped from the passed
  // string.
  using OutputCallback = base::RepeatingCallback<void(base::StringPiece)>;

  // Sets the output callback to call when the process writes messages to its
  // stdout or stderr.
  void SetOutputCallback(OutputCallback callback) {
    output_callback_ = std::move(callback);
  }

  // Callback called when the 'launcher' process finished.
  using LauncherExitCallback = base::OnceCallback<void(int exit_code)>;

  // Sets the callback to call when the 'launcher' process finished.
  void SetLauncherExitCallback(LauncherExitCallback callback);

  // Starts the 'launcher' process. Returns true in case of success. Once
  // started, the process can be waiting for to finish using Wait().
  bool Start();

  // Waits for the 'launcher' process to finish and returns its exit code.
  int Wait();

  // Checks if the 'launcher' process finished, in a non-blocking way.
  bool IsFinished();

  // Starts a process, captures its output and waits for it to finish. Returns
  // the same exit code as Wait().
  int Run();

  // Gets all the messages written by the subprocess to its stdout and stderr,
  // split into lines.
  const std::vector<std::string>& GetCapturedOutput() const {
    return captured_output_;
  }

  // Request the termination of the PID namespace. Returns true if the request
  // was taken in account. This method does not block, and does not wait for the
  // PID namespace to be actually killed.
  virtual bool KillPidNamespace() { return false; }

  // Gets the Process ID (PID) of the subprocess. If the subprocess is running
  // in a PID namespace (see class SandboxedProcess), then this gets the PID of
  // the 'init' process of the PID namespace, not the PID of the 'launcher'
  // process or the 'daemon' process. If the subprocess is not running in a PID
  // namespace, then this gets the PID of the 'launcher' process.
  pid_t pid() const { return pid_; }

  // Gets the name of the program (from the first argument passed to
  // AddArgument()).
  std::string GetProgramName() const { return program_name_; }

  const std::vector<std::string>& arguments() const { return arguments_; }
  const std::vector<std::string>& environment() const { return environment_; }
  const std::string& input() const { return input_; }

 protected:
  Process();

  // Gets the arguments used to start the process. This method calls
  // BuildArgumentsArray() to build |arguments_array_| only once (i.e. when
  // |arguments_array_| is empty). Once |arguments_array_| is built, subsequent
  // calls to AddArgument() are not allowed. The returned array of arguments is
  // owned by this Process object.
  char* const* GetArguments();

  // Gets the environment to pass to the subprocess. The returned array of
  // environment variables is owned by this Process object.
  char* const* GetEnvironment();

  // Starts a process, and connects to its stdin, stdout and stderr the given
  // file descriptors.
  //
  // Returns the PID of the started process, or -1 in case of error.
  virtual pid_t StartImpl(base::ScopedFD in_fd, base::ScopedFD out_fd) = 0;

  // Once either WaitImpl() or WaitNonBlockingImpl() has returned a nonnegative
  // exit code, none of these methods is called again.

  // Waits for the process to finish and returns its nonnegative exit code.
  virtual int WaitImpl() = 0;

  // Checks if the process has finished and returns its nonnegative exit code,
  // or -1 if the process is still running.
  virtual int WaitNonBlockingImpl() = 0;

  // Called when the 'launcher' process finished.
  void OnLauncherExit();

  // Pipe through which the exit code of the 'launcher' process
  // will be communicated. Only used when |use_pid_namespace_| is true.
  SubprocessPipe launcher_pipe_{SubprocessPipe::kChildToParent};

  // Callback to call when the 'launcher' process finished.
  LauncherExitCallback launcher_exit_callback_;

  // Watch controller for |launcher_pipe_|.
  std::unique_ptr<base::FileDescriptorWatcher::Controller> launcher_watch_;

 private:
  // Starts the process. The started process has its stdin, stdout and stderr
  // redirected to the given file descriptors. Returns true in case of success.
  bool Start(base::ScopedFD in_fd, base::ScopedFD out_fd);

  // Called when one line of the subprocess output has been received. Stores
  // this line in |captured_output_|, and calls |output_callback_| with it if
  // necessary.
  void StoreOutputLine(base::StringPiece line);

  // Splits |data| into lines and calls |StoreOutputLine| as many times as
  // necessary.
  void SplitOutputIntoLines(base::StringPiece data);

  // Reads data from |out_fd_|, and calls |SplitOutputIntoLines| with it.
  //
  // Returns true if there might be more data to read in the future, or false if
  // the end of stream has definitely been reached.
  bool CaptureOutput();

  // Waits up to 100 ms for something to read from |out_fd_|, and calls
  // |CaptureOutput()| if necessary.
  //
  // Returns true if there might be more data to read in the future, or false if
  // the end of stream has definitely been reached.
  bool WaitAndCaptureOutput();

  // Flushes |remaining_| into |output_callback_| if necessary. Closes
  // |out_fd_|.
  void FlushOutput();

  // Called when there is an asynchronous indication that some data is available
  // in |out_fd_|. Calls |CaptureOutput|.
  void OnOutputAvailable();

  // Builds |arguments_array_| from |arguments_|. Existing values of
  // |arguments_array_| are overridden.
  void BuildArgumentsArray();

  bool finished() const { return exit_code_ >= 0; }

  // Program name.
  std::string program_name_;

  // Process arguments.
  std::vector<std::string> arguments_;
  std::vector<char*> arguments_array_;

  // Extra environment variables.
  std::vector<std::string> environment_;

  // Full environment for the subprocess.
  std::vector<char*> environment_array_;

  // String to pass to the process stdin.
  std::string input_;

  // Process ID (default to kInvalidProcessId when the process has not started).
  pid_t pid_ = kInvalidProcessId;

  // Exit code. A nonnegative value indicates that the process has finished.
  int exit_code_ = -1;

  // Read end of the pipe that is collecting the stdout and stderr of the
  // subprocess.
  base::ScopedFD out_fd_;

  // Captured subprocess output read from |out_fd_| and split into lines.
  std::vector<std::string> captured_output_;

  // Last partially collected line read from |out_fd_|.
  std::string remaining_;

  // Output callback to call when the subprocess writes messages to its stdout
  // or stderr.
  OutputCallback output_callback_;

  std::unique_ptr<base::FileDescriptorWatcher::Controller> output_watch_;

  FRIEND_TEST(ProcessTest, GetArguments);
  FRIEND_TEST(ProcessTest, GetArgumentsWithNoArgumentsAdded);
};

std::ostream& operator<<(std::ostream& out, Process::ExitCode exit_code);

}  // namespace cros_disks

#endif  // CROS_DISKS_PROCESS_H_
