// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MINIOS_MOCK_PROCESS_MANAGER_H_
#define MINIOS_MOCK_PROCESS_MANAGER_H_

#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "minios/process_manager_interface.h"

class MockProcessManager : public ProcessManagerInterface {
 public:
  MockProcessManager() = default;
  ~MockProcessManager() = default;

  MockProcessManager(const MockProcessManager&) = delete;
  MockProcessManager& operator=(const MockProcessManager&) = delete;

  MOCK_METHOD(int,
              RunCommand,
              (const std::vector<std::string>& cmd,
               const ProcessManagerInterface::IORedirection& io_redirection),
              (override));

  MOCK_METHOD(bool,
              RunBackgroundCommand,
              (const std::vector<std::string>& cmd,
               const ProcessManagerInterface::IORedirection& io_redirection,
               pid_t* pid),
              (override));

  MOCK_METHOD(bool,
              RunCommandWithOutput,
              (const std::vector<std::string>& cmd,
               int* return_code,
               std::string* stdout_out,
               std::string* stderr_out),
              (override));
};

#endif  // MINIOS_MOCK_PROCESS_MANAGER_H_
