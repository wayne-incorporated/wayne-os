// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This program is run directly by the kernel for all programs the kernel runs.
// See the CONFIG_STATIC_USERMODEHELPER setting.

#include "init/usermode-helper.h"

#include <unistd.h>

#include <string>

#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/syslog_logging.h>

int main(int argc, const char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // When running locally for testing, argv[0] will be usermode-helper itself.
  // When the kernel invokes us, argv[0] will be set to the program it wants
  // us to run.  So only shift argv when it makes sense.
  if (strcmp(basename(argv[0]), "usermode-helper") == 0) {
    // Allow users to run this directly and figure out what it is.  It's not
    // uncommon for curious people to run it directly or pass --help.
    if (argc == 1 || strcmp(argv[1], "-h") == 0 ||
        strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-help") == 0) {
      LOG(INFO) << "usermode-helper securely filters the programs the kernel "
                << "is allowed to run.";
      return 0;
    }

    --argc;
    ++argv;
  }

  if (argc < 1)
    LOG(FATAL) << "missing program to run";

  // Validate the program and its arguments, and reject all others.
  if (!usermode_helper::ValidateProgramArgs(argc, argv)) {
    base::CommandLine cmdline(argc, argv);
    LOG(FATAL) << "program invocation not permitted: "
               << cmdline.GetCommandLineString();
  }

  // We could use execveat(), but it's not a clear win.
  // Pros:
  //  - We guarantee the program is in the rootfs (/) and people can't bind
  //    mount over paths to confuse us.
  //  - The kernel doesn't allow scripts (i.e. files with #! shebangs) to be
  //    executed through execveat.  Might be a bug?
  //  - We could require all programs not be symlinked.
  // Cons:
  //  - Some programs we permit are actually symlinks (e.g. modprobe is a
  //    symlink to kmod).  We have an image test that verifies all symlinks in
  //    the rootfs are sane, so not exactly a win.
  //  - Some standard programs use #! to redirect themselves (e.g. coreutils
  //    uses it for all of its programs).  Not clear that banning scripts when
  //    we've already validated the argv is a win.
  //
  // So we stick with execv for now.
  execv(argv[0], const_cast<char**>(argv));
  if (errno == ENOENT) {
    // If the exec failed because the program doesn't exist, we've already
    // checked that the invocation was OK above, so just exit silently here.
    // We use 127 to semi-mimic POSIX shell behavior which exits 127 when a
    // program is not found.
    return 127;
  }
  PLOG(FATAL) << "execing program failed: " << argv[0];
}
