// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Make sure to pass (at least) cheets_SELinuxTest, cheets_ContainerMount,
// cheets_DownloadsFilesystem, cheets_FileSystemPermissions, and
// cheets_PerfBoot auto tests.
//
// For unit testing, see arc_setup_util_unittest.cc.

#include <string>

#include <base/at_exit.h>
#include <base/check.h>
#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/timer/elapsed_timer.h>
#include <base/logging.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "arc/setup/arc_setup.h"

namespace {

arc::Mode GetMode(const std::string& mode) {
  static constexpr std::pair<const char*, arc::Mode> kModeNameMapping[] = {
      {"setup", arc::Mode::SETUP},
      {"boot-continue", arc::Mode::BOOT_CONTINUE},
      {"stop", arc::Mode::STOP},
      {"onetime-setup", arc::Mode::ONETIME_SETUP},
      {"onetime-stop", arc::Mode::ONETIME_STOP},
      {"pre-chroot", arc::Mode::PRE_CHROOT},
      {"remove-data", arc::Mode::REMOVE_DATA},
      {"mount-sdcard", arc::Mode::MOUNT_SDCARD},
      {"unmount-sdcard", arc::Mode::UNMOUNT_SDCARD},
      {"update-restorecon-last", arc::Mode::UPDATE_RESTORECON_LAST},
      {"remove-stale-data", arc::Mode::REMOVE_STALE_DATA},
  };
  for (const auto& mode_name : kModeNameMapping) {
    if (mode == mode_name.first)
      return mode_name.second;
  }

  CHECK(false) << "Invalid mode '" << mode << "'";
  return arc::Mode::UNKNOWN;
}

}  // namespace

int main(int argc, char** argv) {
  DEFINE_string(log_tag, "", "Tag to be used in syslog");
  DEFINE_string(mode, "", "arc-setup mode of operation");
  DEFINE_bool(create_tagged_ashmem, false,
              "creates /dev/ashmem{boot_id} with device type equal to the "
              "host's /dev/ashmem (only valid in pre-chroot mode)");

  base::ElapsedTimer timer;
  base::AtExitManager at_exit;

  brillo::FlagHelper::Init(argc, argv, "ARC setup");

  CHECK(!FLAGS_log_tag.empty()) << "Must specify --log_tag";
  brillo::OpenLog(FLAGS_log_tag.c_str(), true /*log_pid*/);

  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  const std::string command_line =
      base::CommandLine::ForCurrentProcess()->GetCommandLineString();
  LOG(INFO) << "Starting " << command_line;
  {
    arc::ArcSetup setup(GetMode(FLAGS_mode),
                        base::FilePath(arc::kContainerConfigJson));
    setup.set_create_tagged_ashmem(FLAGS_create_tagged_ashmem);
    setup.Run();
  }
  LOG(INFO) << command_line << " took "
            << timer.Elapsed().InMillisecondsRoundedUp() << "ms";
  return 0;
}
