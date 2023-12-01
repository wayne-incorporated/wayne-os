// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "init/clobber_state.h"

#include <unistd.h>

#include <memory>

#include <base/files/file.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <brillo/blkdev_utils/lvm.h>

#include "init/crossystem_impl.h"

namespace {

base::File OpenTerminal() {
  base::FilePath terminal_path;
  if (base::PathExists(base::FilePath("/sbin/frecon"))) {
    terminal_path = base::FilePath("/run/frecon/vt0");
  } else {
    terminal_path = base::FilePath("/dev/tty1");
  }
  base::File terminal =
      base::File(terminal_path, base::File::FLAG_OPEN | base::File::FLAG_WRITE);

  if (!terminal.IsValid()) {
    PLOG(WARNING) << "Could not open terminal " << terminal_path.value()
                  << " falling back to /dev/null";
    terminal = base::File(base::FilePath("/dev/null"),
                          base::File::FLAG_OPEN | base::File::FLAG_WRITE);
  }

  return terminal;
}

}  // namespace

int main(int argc, char* argv[]) {
  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_FILE;
  settings.log_file_path = "/tmp/clobber-state.log";
  // All logging happens in the main thread, so there is no need to lock the log
  // file.
  settings.lock_log = logging::DONT_LOCK_LOG_FILE;
  settings.delete_old = logging::DELETE_OLD_LOG_FILE;
  logging::InitLogging(settings);

  if (getuid() != 0) {
    LOG(ERROR) << argv[0] << " must be run as root";
    return 1;
  }

  ClobberState::Arguments args = ClobberState::ParseArgv(argc, argv);
  ClobberState clobber(args, std::make_unique<CrosSystemImpl>(),
                       std::make_unique<ClobberUi>(OpenTerminal()),
                       std::make_unique<brillo::LogicalVolumeManager>());

  return clobber.Run();
}
