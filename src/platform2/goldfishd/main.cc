// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
//
// goldfishd - A daemon to get message from host when running Chrome OS inside
// Android Emulator.

#include <fcntl.h>
#include <stdlib.h>
#include <sysexits.h>

#include <base/files/file_descriptor_watcher_posix.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/process/launch.h>
#include <base/time/time.h>
#include <brillo/daemons/daemon.h>
#include <brillo/flag_helper.h>
#include <brillo/message_loops/message_loop.h>
#include <brillo/syslog_logging.h>

#include "goldfishd/goldfish_library.h"

namespace {

// QEMUD service connection request to open Chrome OS channel.
const char kCrosPipe[] = "pipe:qemud:cros";
// Character device provided by Android Emulator.
const char kGoldfishDev[] = "/dev/goldfish_pipe";
// Timeout to wait auto login script to finish.
constexpr base::TimeDelta kLoginTimeout = base::Seconds(50);

class GoldfishDaemon : public brillo::Daemon {
 public:
  GoldfishDaemon() = default;
  GoldfishDaemon(const GoldfishDaemon&) = delete;
  GoldfishDaemon& operator=(const GoldfishDaemon&) = delete;

 private:
  void DoAutoLogin() {
    std::vector<std::string> args = {
        "/usr/local/autotest/bin/autologin.py",
        "-a",
    };
    base::LaunchOptions options;
    base::Process child = base::LaunchProcess(args, options);
    int exit_code;
    if (!child.WaitForExitWithTimeout(kLoginTimeout, &exit_code)) {
      LOG(ERROR) << "Timeout exceeded running autologin";
      if (!child.Terminate(0, true))
        LOG(ERROR) << "Failed to terminate autololgin";
      return;
    }
    if (exit_code) {
      LOG(ERROR) << "Failed to run autologin, exited with status " << exit_code;
    }
  }

  void HandleHostMessage() {
    std::string message;
    if (!goldfishd::ReadOneMessage(fd_.get(), &message)) {
      brillo::MessageLoop::current()->BreakLoop();
      return;
    }

    LOG(INFO) << "Host send: " << message;
    if (message == goldfishd::message::kAutoLogin) {
      DoAutoLogin();
    } else {
      LOG(WARNING) << "Unsupported message: " << message;
    }
  }

  int OnInit() override {
    fd_ = base::ScopedFD(open(kGoldfishDev, O_RDWR));
    if (!fd_.is_valid()) {
      LOG(WARNING) << "Can't open " << kGoldfishDev;
      return EX_UNAVAILABLE;
    }
    struct stat st;
    if (fstat(fd_.get(), &st) < 0) {
      LOG(WARNING) << "Can't stat " << kGoldfishDev;
      return EX_UNAVAILABLE;
    }
    // Sanity check, it should be a char device.
    if (!S_ISCHR(st.st_mode)) {
      LOG(WARNING) << "Not a char device " << kGoldfishDev;
      return EX_UNAVAILABLE;
    }

    if (!base::WriteFileDescriptor(
            fd_.get(), base::StringPiece(kCrosPipe, sizeof(kCrosPipe)))) {
      LOG(WARNING) << "Fail to open cros pipe, old version Android Emulator?";
      return EX_UNAVAILABLE;
    }

    watcher_ = base::FileDescriptorWatcher::WatchReadable(
        fd_.get(), base::BindRepeating(&GoldfishDaemon::HandleHostMessage,
                                       base::Unretained(this)));
    return EX_OK;
  }

  base::ScopedFD fd_;
  std::unique_ptr<base::FileDescriptorWatcher::Controller> watcher_;
};

}  // namespace

int main(int argc, const char* argv[]) {
  brillo::FlagHelper::Init(argc, argv, "goldfishd, Android Emulator daemon");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  GoldfishDaemon daemon;
  int rc = daemon.Run();

  return rc == EX_UNAVAILABLE ? EX_OK : rc;
}
