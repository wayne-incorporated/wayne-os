// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/periodic_scheduler.h"

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

int main(int argc, char** argv) {
  DEFINE_uint64(period, 3600,
                "Time period (in seconds) between successive tasks.");
  DEFINE_uint64(timeout, 600, "Timeout (in seconds) before killing the task.");
  DEFINE_uint64(check_frequency, 0,
                "(For testing) Frequency to check task readiness.");
  DEFINE_string(spool_dir, "",
                "(For testing) Spool directory to store task state.");
  DEFINE_string(task_name, "", "Task name");
  DEFINE_bool(start_immediately, false,
              "Skip waiting before launching the first task instance.");

  brillo::FlagHelper::Init(argc, argv, "Periodic Task Scheduler");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  std::vector<std::string> args =
      base::CommandLine::ForCurrentProcess()->GetArgs();

  if (FLAGS_task_name.empty()) {
    FLAGS_task_name = base::FilePath(args[0]).BaseName().value();
  }

  PeriodicScheduler p(base::Seconds(FLAGS_period), base::Seconds(FLAGS_timeout),
                      FLAGS_task_name, args);

  if (!FLAGS_spool_dir.empty())
    p.set_spool_dir_for_test(base::FilePath(FLAGS_spool_dir));

  if (FLAGS_check_frequency != 0) {
    p.set_check_freq_for_test(base::Seconds(FLAGS_check_frequency));
  }

  return p.Run(FLAGS_start_immediately) == true ? 0 : 1;
}
