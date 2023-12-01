// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/bluetooth_devcd_parser_util.h"

#include <base/files/file_path.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

int main(int argc, char* argv[]) {
  DEFINE_string(coredump_path, "", "Coredump file path");
  DEFINE_string(output_dir, "", "Output dir path");
  DEFINE_bool(save_dump_data, false, "Save binary dump data");
  DEFINE_bool(enable_syslog, false, "Print logs to syslog");

  brillo::FlagHelper::Init(argc, argv, "ChromeOS Bluetooth Crash Parser");

  brillo::OpenLog("bluetooth_devcd_parser", true);
  if (FLAGS_enable_syslog) {
    brillo::InitLog(brillo::kLogToSyslog);
  } else {
    brillo::InitLog(brillo::kLogToStderr);
  }

  std::string crash_sig;
  if (!bluetooth_util::ParseBluetoothCoredump(
          base::FilePath(FLAGS_coredump_path), base::FilePath(FLAGS_output_dir),
          FLAGS_save_dump_data, &crash_sig)) {
    LOG(ERROR) << "Failed to parse bluetooth devcoredump.";
    return EXIT_FAILURE;
  }

  LOG(INFO) << "Crash report generated with a signature " << crash_sig;

  return EXIT_SUCCESS;
}
