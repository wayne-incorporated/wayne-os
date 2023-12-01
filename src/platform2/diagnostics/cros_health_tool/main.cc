// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdlib.h>

#include <iostream>
#include <string>

#include <base/at_exit.h>
#include <base/task/single_thread_task_executor.h>
#include <base/task/single_thread_task_runner.h>
#include <brillo/syslog_logging.h>
#include <mojo/core/embedder/embedder.h>
#include <mojo/core/embedder/scoped_ipc_support.h>

#include "diagnostics/cros_health_tool/diag/diag.h"
#include "diagnostics/cros_health_tool/event/event.h"
#include "diagnostics/cros_health_tool/telem/telem.h"

namespace {

void PrintHelp() {
  std::cout << "cros-health-tool" << std::endl;
  std::cout << "    subtools: diag, telem, event" << std::endl;
  std::cout << "    Usage: cros-health-tool {subtool} $@" << std::endl;
  std::cout << "    Help: cros-health-tool {subtool} --help" << std::endl;
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc < 2) {
    PrintHelp();
    return EXIT_FAILURE;
  }

  brillo::InitLog(brillo::kLogToStderr);

  // Initialize the mojo environment.
  base::AtExitManager at_exit_manager;
  base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
  mojo::core::Init();
  mojo::core::ScopedIPCSupport ipc_support(
      base::SingleThreadTaskRunner::
          GetCurrentDefault() /* io_thread_task_runner */,
      mojo::core::ScopedIPCSupport::ShutdownPolicy::
          CLEAN /* blocking shutdown */);

  // Shift input parameters so they can be forwarded directly to the subtool.
  int subtool_argc = argc - 1;
  char** subtool_argv = &argv[1];

  std::string subtool = subtool_argv[0];
  if (subtool == "diag") {
    return diagnostics::diag_main(subtool_argc, subtool_argv);
  } else if (subtool == "event") {
    return diagnostics::event_main(subtool_argc, subtool_argv);
  } else if (subtool == "telem") {
    return diagnostics::telem_main(subtool_argc, subtool_argv);
  } else if (subtool == "help" || subtool == "--help" || subtool == "-h") {
    PrintHelp();
    return EXIT_SUCCESS;
  } else {
    PrintHelp();
  }

  return EXIT_FAILURE;
}
