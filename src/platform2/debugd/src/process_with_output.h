// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEBUGD_SRC_PROCESS_WITH_OUTPUT_H_
#define DEBUGD_SRC_PROCESS_WITH_OUTPUT_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <brillo/errors/error.h>

#include "debugd/src/sandboxed_process.h"

namespace debugd {

// Represents a process whose output can be collected.
//
// The process must be Run() to completion before its output can be collected.
// By default both stdout and stderr are included in the output.
class ProcessWithOutput : public SandboxedProcess {
 public:
  using ArgList = std::vector<std::string>;

  static constexpr int kRunError = -1;

  ProcessWithOutput();
  ~ProcessWithOutput() override;
  bool Init() override;
  bool Init(const std::vector<std::string>& minijail_extra_args) override;
  bool GetOutput(std::string* output) const;
  bool GetOutputLines(std::vector<std::string>* output) const;

  // Reads the stderr output. Must have called set_separate_stderr(true) and
  // run the process to completion.
  bool GetError(std::string* error);

  // Separates stderr from stdout. Must be called before Init() to have effect.
  void set_separate_stderr(bool separate_stderr) {
    separate_stderr_ = separate_stderr;
  }

  // Sets whether to use Minijail or not. Disabling Minijail will omit all
  // sandboxing functionality from the process, and should only be used from
  // within helper programs that are already sandboxed. The purpose of this is
  // to allow the process to search PATH for the executable, since Minijail does
  // not support this.
  // This must be called before Init() to have any effect. Defaults to true.
  void set_use_minijail(bool use_minijail) { use_minijail_ = use_minijail; }

  // Initializes, configures, and runs a ProcessWithOutput. If |disable_sandbox|
  // is set, |requires_root| will be ignored. The D-Bus error will only be set
  // if process setup fails, it's up to the caller to check the process exit
  // code and handle run failures as needed.
  // |stdin| is a string to pipe into the process, and |stdout| and |stderr|
  // will be filled with the corresponding process output. |error| will be
  // set if process setup fails and the process was never able to run. All
  // four of these parameters can be null.
  // Returns the process exit code or kRunError on setup failure.
  static int RunProcess(const std::string& command,
                        const ArgList& arguments,
                        bool requires_root,
                        bool disable_sandbox,
                        const std::string* stdin,
                        std::string* stdout,
                        std::string* stderr,
                        brillo::ErrorPtr* error);

  // Like RunProcess() but to run helper programs. |helper| should be specified
  // relative to the helpers/ directory.
  static int RunHelper(const std::string& helper,
                       const ArgList& arguments,
                       bool requires_root,
                       const std::string* stdin,
                       std::string* stdout,
                       std::string* stderr,
                       brillo::ErrorPtr* error);

  // Like RunProcess() but from within helper programs. This function will
  // not use minijail0 or any sandboxing (since helper programs should already
  // be sandboxed) and $PATH will be searched to execute |command|.
  static int RunProcessFromHelper(const std::string& command,
                                  const ArgList& arguments,
                                  const std::string* stdin,
                                  std::string* stdout,
                                  std::string* stderr);

 private:
  base::FilePath outfile_path_, errfile_path_;
  base::ScopedFILE outfile_, errfile_;
  bool separate_stderr_, use_minijail_;

  // Private function to do the work of running the process and handling I/O.
  static int DoRunProcess(const std::string& command,
                          const ArgList& arguments,
                          const std::string* stdin,
                          std::string* stdout,
                          std::string* stderr,
                          brillo::ErrorPtr* error,
                          ProcessWithOutput* process);
};

}  // namespace debugd

#endif  // DEBUGD_SRC_PROCESS_WITH_OUTPUT_H_
