// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is kept small as it cannot be unittested (due to the main func).
// So it should only initialie the CLI interface before calling into the
// dedicated DevInstall class.

#include "dev-install/dev_install.h"

#include <unistd.h>

#include <string>

#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

using dev_install::DevInstall;

int main(int argc, char* argv[]) {
  DEFINE_string(binhost, "", "URL of the binhost that emerge will use");
  DEFINE_string(binhost_version, "",
                "Version number to use instead of the one in /etc/lsb-release");
  DEFINE_bool(reinstall, false,
              "Remove all installed packages and re-bootstrap emerge");
  DEFINE_bool(uninstall, false, "Remove all installed packages");
  DEFINE_bool(yes, false,
              "Do not prompt for input -- assume yes to all responses");
  DEFINE_bool(only_bootstrap, false,
              "Only attempt to install the bootstrap packages");
  DEFINE_uint32(jobs, 0, "How many install jobs to run in parallel");

  brillo::FlagHelper::Init(argc, argv,
                           "Chromium OS Development Image Installer");

  // This tool is only run by devs, so writing to syslog doesn't make sense.
  brillo::InitLog(brillo::kLogToStderr);

  const base::CommandLine* cl = base::CommandLine::ForCurrentProcess();
  if (cl->GetArgs().size() > 0) {
    LOG(ERROR) << "Unknown extra command line arguments; exiting";
    return EXIT_FAILURE;
  }

  if (FLAGS_uninstall && FLAGS_reinstall) {
    LOG(ERROR) << "--reinstall & --uninstall may not be used together";
    return EXIT_FAILURE;
  }

  if (getuid() != 0) {
    LOG(ERROR) << argv[0] << " must be run as root";
    return EXIT_FAILURE;
  }

  DevInstall dev_install(FLAGS_binhost, FLAGS_binhost_version, FLAGS_reinstall,
                         FLAGS_uninstall, FLAGS_yes, FLAGS_only_bootstrap,
                         FLAGS_jobs);
  return dev_install.Run();
}
