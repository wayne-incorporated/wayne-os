// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "secure_erase_file/secure_erase_file.h"

#include <sysexits.h>

#include <base/command_line.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

int main(int argc, const char* const argv[]) {
  DEFINE_bool(zero_out, false,
              "Use WRITEZERO instead of BLKSECDISCARD, which is more widely "
              "supported but less secure.");
  brillo::FlagHelper::Init(argc, argv, "Secure erase tool.");

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderr |
                  brillo::kLogHeader);

  base::CommandLine::Init(argc, argv);
  base::CommandLine::StringVector files =
      base::CommandLine::ForCurrentProcess()->GetArgs();
  if (files.size() < 1) {
    LOG(WARNING) << "At least one file argument must be provided.";
    return EX_USAGE;
  }

  // Use a status variable to erase all the files we possibly can, then drop
  // caches. We still return an error if any files have failed so that external
  // scripts can react accordingly.
  bool ok = true;
  for (const auto& file : files) {
    if (FLAGS_zero_out) {
      ok &= secure_erase_file::ZeroFile(base::FilePath(file));
    } else {
      ok &= secure_erase_file::SecureErase(base::FilePath(file));
    }
  }
  ok &= secure_erase_file::DropCaches();
  return ok ? 0 : EX_IOERR;
}
