// Copyright 2010 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>

#include <base/command_line.h>
#include <base/logging.h>

#include "image-burner/daemon.h"

int main(int argc, char* argv[]) {
  base::CommandLine::Init(argc, argv);

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_ALL;
  settings.log_file_path = "/var/log/image_burner.log";
  settings.lock_log = logging::LOCK_LOG_FILE;
  settings.delete_old = logging::DELETE_OLD_LOG_FILE;
  logging::InitLogging(settings);

  imageburn::Daemon daemon;
  return daemon.Run();
}
