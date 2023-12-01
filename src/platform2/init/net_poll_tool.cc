// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sysexits.h>
#include <time.h>
#include <unistd.h>

#include <base/files/file_path.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/notreached.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

namespace {

// A flag for the busy loops below to check.
volatile bool timedout = false;

void SigalarmHandler(int sig) {
  timedout = true;
}

// Sleep for a very short period of time.  We want the kernel to schedule
// something else (hopefully whatever we're waiting for) before coming back.
void Yield(const std::string& desc) {
  const struct timespec ts = {
      .tv_sec = 0,
      .tv_nsec = 1000 * 1000,  // 1 millisecond.
  };
  nanosleep(&ts, nullptr);
  if (timedout) {
    LOG(ERROR) << "Request timed out: " << desc;
    exit(EX_UNAVAILABLE);
  }
}

// Poll a UNIX socket until it's usable.
bool PollUnixSocket(const base::FilePath& path) {
  base::ScopedFD s(
      socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0));
  if (!s.is_valid()) {
    PLOG(ERROR) << "Could not create a UNIX socket";
    return false;
  }

  struct sockaddr_un sa;

  // We want > here and not >= as Linux supports a path that is not explicitly
  // NUL terminated if the path fills the entire buffer.
  if (path.value().length() > sizeof(sa.sun_path)) {
    LOG(ERROR) << "Path is too long for a UNIX socket: " << path.value();
    return false;
  }

  memset(&sa, 0, sizeof(sa));
  sa.sun_family = AF_UNIX;
  // The memset above took care of NUL terminating, and we already verified
  // the length before that.
  memcpy(sa.sun_path, path.value().data(), path.value().length());

  while (connect(s.get(), reinterpret_cast<struct sockaddr*>(&sa),
                 sizeof(sa)) == -1) {
    if (errno != ECONNREFUSED && errno != ENOENT && errno != EAGAIN) {
      PLOG(ERROR) << "connect(" << path.value() << ") failed";
      return false;
    }
    Yield(path.value());
  }

  return true;
}

}  // namespace

int main(int argc, char* argv[]) {
  DEFINE_int32(timeout, 0, "How many seconds to wait (0 for forever)");
  DEFINE_string(unix_socket, "", "Path to a UNIX socket");
  brillo::FlagHelper::Init(argc, argv, "Chromium OS Network Poller");
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogToStderrIfTty);

  // Check for conflicting options.
  if (FLAGS_unix_socket.empty()) {
    LOG(ERROR) << "Missing socket to poll; please see --help";
    return EX_USAGE;
  }

  // Do the actual polling now.
  if (FLAGS_timeout > 0) {
    signal(SIGALRM, SigalarmHandler);
    alarm(FLAGS_timeout);
  }

  if (!FLAGS_unix_socket.empty()) {
    base::FilePath unix_socket(FLAGS_unix_socket);
    return PollUnixSocket(unix_socket) ? EX_OK : 1;
  }

  NOTREACHED() << "Parsing logic error";
}
