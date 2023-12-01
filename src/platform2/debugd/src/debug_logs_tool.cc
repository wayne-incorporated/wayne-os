// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "debugd/src/debug_logs_tool.h"
#include "debugd/src/log_tool.h"

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <brillo/process/process.h>

namespace debugd {

namespace {

constexpr char kFeedbackLogsDir[] = "feedback";

constexpr char kTar[] = "/bin/tar";
constexpr char kSystemLogs[] = "/var/log";
constexpr char kCrashLogs[] = "/var/spool/crash";

}  // namespace

void DebugLogsTool::GetDebugLogs(bool is_compressed, const base::ScopedFD& fd) {
  base::ScopedTempDir temp_dir;
  if (!temp_dir.CreateUniqueTempDir()) {
    PLOG(WARNING) << "Failed to create a temporary directory";
    return;
  }

  base::FilePath logs_path = temp_dir.GetPath().Append(kFeedbackLogsDir);
  if (!base::CreateDirectory(logs_path)) {
    PLOG(WARNING) << "Failed to create dir: " << logs_path.value();
    return;
  }

  LogTool log_tool(bus_, perf_logging_);
  LogTool::LogMap logs = log_tool.GetAllDebugLogs();
  for (const auto& l : logs) {
    const std::string& name = l.first;
    const std::string& contents = l.second;
    if (base::WriteFile(logs_path.Append(name), contents.data(),
                        contents.size()) < 0) {
      PLOG(WARNING) << "Failed to write file: " << name;
    }
  }

  brillo::ProcessImpl p;
  p.AddArg(kTar);
  p.AddArg("-c");
  if (is_compressed)
    p.AddArg("-z");
  p.AddArg("-C");
  p.AddArg(temp_dir.GetPath().value());
  p.AddArg(kFeedbackLogsDir);
  p.AddArg(kSystemLogs);
  p.AddArg(kCrashLogs);
  p.BindFd(fd.get(), STDOUT_FILENO);
  p.Run();
}

}  // namespace debugd
