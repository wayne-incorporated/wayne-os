// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_PROCESS_MANAGER_H_
#define MINIOS_PROCESS_MANAGER_H_

#include <memory>
#include <string>
#include <vector>

#include <brillo/process/process.h>

#include "minios/process_manager_interface.h"

class ProcessManager : public ProcessManagerInterface {
 public:
  ProcessManager() = default;
  ~ProcessManager() = default;

  // ProcessManagerInterface overrides these functions.

  // Runs the command line with input and output redirected and returns the exit
  // code. Input and output files will be ignored if strings are empty.
  int RunCommand(
      const std::vector<std::string>& cmd,
      const ProcessManagerInterface::IORedirection& io_redirection) override;

  // Starts the command line with the input and output redirected in the
  // background, returns true on success and sets pid. Input and output files
  // will be ignored if the strings are empty.
  bool RunBackgroundCommand(
      const std::vector<std::string>& cmd,
      const ProcessManagerInterface::IORedirection& io_redirection,
      pid_t* pid) override;

  // Runs the command and reads the output and error to the strings. Returns
  // false or sets the return code and stderr message on failure.
  bool RunCommandWithOutput(const std::vector<std::string>& cmd,
                            int* return_code,
                            std::string* stdout_out,
                            std::string* stderr_out) override;

 private:
  ProcessManager(const ProcessManager&) = delete;
  ProcessManager& operator=(const ProcessManager&) = delete;

  std::unique_ptr<brillo::Process> CreateProcess(
      const std::vector<std::string>& cmd,
      const ProcessManagerInterface::IORedirection& io_redirection);
};

#endif  // MINIOS_PROCESS_MANAGER_H_
