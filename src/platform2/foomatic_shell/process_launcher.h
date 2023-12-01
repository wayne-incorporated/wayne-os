// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef FOOMATIC_SHELL_PROCESS_LAUNCHER_H_
#define FOOMATIC_SHELL_PROCESS_LAUNCHER_H_

#include <sys/types.h>

#include <memory>
#include <set>
#include <string>

#include "foomatic_shell/grammar.h"

namespace brillo {
class Process;
}

namespace foomatic_shell {

// Exit code reported when an error occurs of the shell side.
constexpr int kShellError = 127;
// Exit code reported when ghostscript caught SIGXPU signal (CPU time limit was
// reached).
constexpr int kProcTimeLimitError = 126;

// This class is responsible for executing given Script object. It launches
// all commands and subshells from the Script in a correct order and join them
// with pipes. All errors are reported to standard error stream.
class ProcessLauncher {
 public:
  // Constructor. |source| is a reference to original sources of executed
  // script and it must be constant and valid during the lifetime of the
  // object. |source| is used only for building error messages.
  // |verbose_mode| activates additional logs on stderr.
  explicit ProcessLauncher(const std::string& source, bool verbose_mode)
      : source_(source), verbose_(verbose_mode) {}

  // This method executes the given |script|. A file descriptor |input_fd| is
  // connected as a standard input stream for executed script, while a file
  // descriptor |output_fd| is connected as a standard output stream. The
  // execution is stopped on the first failing pipeline. The method returns
  // exit code of the last executed pipeline. Only zero guarantees that the
  // whole script was executed.
  int RunScript(const Script& script, int input_fd, int output_fd);

 private:
  // Helper methods.
  int RunPipeline(const Pipeline& pipeline, int input_fd, int output_fd);
  std::unique_ptr<brillo::Process> StartProcess(const Command& command,
                                                int input_fd,
                                                int output_fd);
  pid_t StartSubshell(const Script& script, int input_fd, int output_fd);

  // This field holds the reference to the script's source provided in the
  // constructor.
  const std::string& source_;
  // This field enables additional logging.
  bool verbose_;
};

}  // namespace foomatic_shell

#endif  // FOOMATIC_SHELL_PROCESS_LAUNCHER_H_
