// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <sysexits.h>

#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "modemfwd/daemon.h"
#include "modemfwd/logging.h"

int main(int argc, char** argv) {
  DEFINE_bool(debug_mode, false, "Turn on debug logging");
  DEFINE_string(journal_file, "/var/cache/modemfwd/journal",
                "File to read the old journal from and write the new one to");
  DEFINE_string(helper_directory, "/opt/google/modemfwd-helpers",
                "Directory to load modem-specific helpers from");
  DEFINE_string(firmware_directory, "", "Directory to load firmware from");
  brillo::FlagHelper::Init(argc, argv, "Daemon which updates modem firmware.");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  if (FLAGS_debug_mode) {
    LOG(INFO) << "Debug mode is on";
    modemfwd::g_extra_logging = true;
  }

  if (FLAGS_journal_file.empty()) {
    LOG(ERROR) << "No journal file was supplied";
    return EX_USAGE;
  }

  if (FLAGS_helper_directory.empty()) {
    LOG(ERROR) << "Must supply helper directory";
    return EX_USAGE;
  }

  if (FLAGS_firmware_directory.empty()) {
    LOG(ERROR) << "Must supply firmware manifest directory";
    return EX_USAGE;
  }

  LOG(INFO) << "Running modemfwd with firmware directory...";
  modemfwd::Daemon d(FLAGS_journal_file, FLAGS_helper_directory,
                     FLAGS_firmware_directory);
  return d.Run();
}
