// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/file_attrs_cleaner.h"

#include <sysexits.h>

#include <string>
#include <vector>

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

using file_attrs_cleaner::ScanDir;

int main(int argc, char* argv[]) {
  DEFINE_string(skip_dir, "", "Subdirectory name to skip.");
  brillo::FlagHelper::Init(argc, argv, "Chromium OS File Attrs Cleaner");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  if (argc <= 1) {
    LOG(ERROR) << "Need at least one directory to scan.";
    return EX_USAGE;
  }

  std::vector<std::string> skip_recurse;
  if (!FLAGS_skip_dir.empty())
    skip_recurse.push_back(FLAGS_skip_dir);

  auto args = base::CommandLine::ForCurrentProcess()->GetArgs();
  bool ret = true;
  for (const auto& arg : args) {
    if (base::DirectoryExists(base::FilePath(arg))) {
      ret &= ScanDir(arg, skip_recurse);
    } else {
      LOG(ERROR) << "Directory '" << arg << "' does not exist.";
      ret = false;
    }
  }

  return ret ? EX_OK : 1;
}
