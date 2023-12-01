// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_PROCESS_MANAGER_INTERFACE_H_
#define MINIOS_PROCESS_MANAGER_INTERFACE_H_

#include <string>
#include <vector>

#include <brillo/errors/error.h>

class ProcessManagerInterface {
 public:
  virtual ~ProcessManagerInterface() = default;

  ProcessManagerInterface(const ProcessManagerInterface&) = delete;
  ProcessManagerInterface& operator=(const ProcessManagerInterface&) = delete;

  struct IORedirection {
    std::string input;
    std::string output;
  };

  virtual int RunCommand(const std::vector<std::string>& cmd,
                         const IORedirection& io_redirection) = 0;

  virtual bool RunBackgroundCommand(const std::vector<std::string>& cmd,
                                    const IORedirection& io_redirection,
                                    pid_t* pid) = 0;

  virtual bool RunCommandWithOutput(const std::vector<std::string>& cmd,
                                    int* return_code,
                                    std::string* stdout_out,
                                    std::string* stderr_out) = 0;

 protected:
  ProcessManagerInterface() = default;
};

#endif  // MINIOS_PROCESS_MANAGER_INTERFACE_H_
