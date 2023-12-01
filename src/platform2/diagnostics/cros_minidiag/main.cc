// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <unistd.h>

#include <iostream>
#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/process/process.h>
#include <brillo/syslog_logging.h>

#include "diagnostics/cros_minidiag/elog_manager.h"
#include "diagnostics/cros_minidiag/utils.h"

namespace {
constexpr const char kElogTool[] = "elogtool";
constexpr const char kList[] = "list";
constexpr const char kListArg[] = "--utc";
constexpr const char kFileLastLine[] = "/var/lib/metrics/elog-last-line";

int GetElogtoolString(std::string& output) {
  brillo::ProcessImpl elogtool;
  elogtool.SetSearchPath(true);
  elogtool.AddArg(kElogTool);
  elogtool.AddArg(kList);
  elogtool.AddArg(kListArg);
  elogtool.RedirectOutputToMemory(true);

  output = "";
  const int result = elogtool.Run();
  if (result == 0)
    output = elogtool.GetOutputString(STDOUT_FILENO);
  return result;
}
}  // namespace

int main(int argc, char* argv[]) {
  DEFINE_bool(last_report, false, "Only dump the new events since last report");
  DEFINE_bool(update_last_report, false,
              "Update the records of elog last report");
  DEFINE_bool(metrics_launch_count, false,
              "Count and report the metrics of MiniDiag launch count");
  DEFINE_bool(metrics_test_report, false,
              "Count and report the metrics of MiniDiag test report");
  brillo::FlagHelper::Init(argc, argv, "Cros MiniDiag Tool");

  const base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  if (cl->GetArgs().size() > 0) {
    LOG(ERROR) << "Unknown extra command line arguments; exiting";
    return EXIT_FAILURE;
  }

  if (!FLAGS_update_last_report && !FLAGS_metrics_launch_count &&
      !FLAGS_metrics_test_report) {
    LOG(ERROR) << "cros-minidiag-tool cannot be run without updating or "
                  "reporting metrics; exiting";
    return EXIT_FAILURE;
  }

  // Dump the full elogtool list result.
  std::string elogtool_output;
  if (GetElogtoolString(elogtool_output) != 0) {
    LOG(ERROR) << "elogtool failed";
    return EXIT_FAILURE;
  }

  std::string previous_last_line = "";
  base::FilePath file_last_line(kFileLastLine);
  std::string elog_start_str = "";
  // Try to get the last line of previous upload.
  if (FLAGS_last_report) {
    elog_start_str = " since last report";
    if (!cros_minidiag::GetPrevElogLastLine(file_last_line,
                                            previous_last_line)) {
      LOG(WARNING) << "Could not read from " << kFileLastLine
                   << "; fallback to count full elog instead";
    }
  }

  cros_minidiag::ElogManager elog_manager(elogtool_output, previous_last_line);

  // Count and report the metrics of MiniDiag launch count.
  if (FLAGS_metrics_launch_count) {
    LOG(INFO) << "Count and report MiniDiag launch count" << elog_start_str;
    elog_manager.ReportMiniDiagLaunch();
  }

  // Count and report the metrics of MiniDiag test report.
  if (FLAGS_metrics_test_report) {
    LOG(INFO) << "Count and report MiniDiag test report" << elog_start_str;
    elog_manager.ReportMiniDiagTestReport();
  }

  // Get the last line of elog and update /var/lib/metrics/elog-last-line.
  if (FLAGS_update_last_report) {
    LOG(INFO) << "Update the saved last line of elog at: " << kFileLastLine;
    if (!base::WriteFile(file_last_line, elog_manager.last_line())) {
      PLOG(ERROR) << "Could not update " << kFileLastLine;
    }
  }

  return EXIT_SUCCESS;
}
