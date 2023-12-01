// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/task/single_thread_task_executor.h>
#include <base/threading/platform_thread.h>

#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "croslog/config.h"
#include "croslog/viewer_journal.h"
#include "croslog/viewer_plaintext.h"

int main(int argc, char* argv[]) {
  // The following method defines the command line arguments and initializes
  // the brillo's command line parser. See the code for detail.
  croslog::Config config;
  bool parse_result = config.ParseCommandLineArgs(argc, argv);

  // The method above (|croslog::Config::ParseCommandLineArgs|) initializes the
  // command line, so this code needs to be placed after that.
  base::CommandLine* const command_line =
      base::CommandLine::ForCurrentProcess();

  if (!parse_result) {
    command_line->AppendSwitch("help");
    // Calling this method shows the command line usage.
    brillo::FlagHelper::GetInstance()->UpdateFlagValues();
    return 1;
  }

  // Configure the log destination. This should be placed before any code which
  // potentially write logs.
  int log_flags = config.quiet ? 0 : brillo::kLogToStderr;
  // if the stdin is not tty, send logs to syslog as well.
  if (!isatty(0) || command_line->HasSwitch("send-syslog"))
    log_flags |= brillo::kLogToSyslog;
  brillo::InitLog(log_flags);

  switch (config.source) {
    case croslog::SourceMode::JOURNAL_LOG:
      croslog::ViewerJournal viewer;
      return viewer.Run(config) ? 0 : 1;
    case croslog::SourceMode::PLAINTEXT_LOG: {
      // Do not use them directly.
      base::SingleThreadTaskExecutor task_executor(base::MessagePumpType::IO);
      base::AtExitManager at_exit_manager_;

      // TODO(yoshiki): Implement the reader of plaintext logs.
      croslog::ViewerPlaintext viewer(config);
      return viewer.Run() ? 0 : 1;
    }
  }
}
