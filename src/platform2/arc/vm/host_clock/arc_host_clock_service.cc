// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/vm_sockets.h>  // Needs to come after sys/socket.h

#include <base/check.h>
#include <base/files/file_util.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/time/time.h>
#include <brillo/syslog_logging.h>
#include <chromeos/constants/vm_tools.h>

int main(int argc, char* argv[]) {
  brillo::InitLog(brillo::kLogToSyslog | brillo::kLogHeader |
                  brillo::kLogToStderrIfTty);

  // Set realtime priority. 10 is the same value as vm_concierge.
  const struct sched_param param = {
      .sched_priority = 10,
  };
  PCHECK(sched_setscheduler(0, SCHED_RR, &param) == 0);

  base::ScopedFD listen_fd(socket(AF_VSOCK, SOCK_STREAM | SOCK_CLOEXEC, 0));
  PCHECK(listen_fd.is_valid());

  constexpr struct sockaddr_vm addr = {
      .svm_family = AF_VSOCK,
      .svm_port = vm_tools::kArcHostClockServicePort,
      .svm_cid = VMADDR_CID_ANY,
  };
  PCHECK(bind(listen_fd.get(), reinterpret_cast<const struct sockaddr*>(&addr),
              sizeof(addr)) == 0);
  PCHECK(listen(listen_fd.get(), 1) == 0);

  // Keep accepting incoming connection.
  while (true) {
    struct sockaddr_vm addr = {};
    socklen_t addr_size = sizeof(addr);
    base::ScopedFD fd(HANDLE_EINTR(
        accept4(listen_fd.get(), reinterpret_cast<struct sockaddr*>(&addr),
                &addr_size, SOCK_CLOEXEC)));
    PCHECK(fd.is_valid());

    // Keep receiving clockid and returning the corresponding clock value.
    while (true) {
      // Maximum number of messages processed in a batch. Chosen arbitrarily.
      constexpr int kNumElements = 16;
      clockid_t message[kNumElements];

      size_t num_bytes = 0;
      bool read_success = false;
      while (!read_success) {
        auto buf = reinterpret_cast<char*>(message) + num_bytes;
        size_t buf_remaining = sizeof(message) - num_bytes;
        ssize_t res = HANDLE_EINTR(read(fd.get(), buf, buf_remaining));
        if (res <= 0) {
          LOG(ERROR) << "Read failed: num_bytes = " << num_bytes << " "
                     << (res < 0 ? logging::SystemErrorCodeToString(
                                       logging::GetLastSystemErrorCode())
                                 : "incomplete message");
          break;
        }
        num_bytes += res;
        read_success = num_bytes % sizeof(message[0]) == 0;
      }

      if (!read_success)
        break;

      const size_t num_requests = num_bytes / sizeof(message[0]);
      int64_t response[kNumElements];
      bool error = false;
      for (size_t idx = 0; idx < num_requests; ++idx) {
        struct timespec ts = {};
        if (clock_gettime(message[idx], &ts) != 0) {
          PLOG(ERROR) << "clock_gettime failed: clock_id = " << message[idx];
          error = true;
          break;
        }
        response[idx] =
            ts.tv_sec * base::Time::kNanosecondsPerSecond + ts.tv_nsec;
      }
      if (error)
        break;

      if (!base::WriteFileDescriptor(
              fd.get(),
              base::StringPiece(reinterpret_cast<const char*>(&response),
                                num_requests * sizeof(response[0])))) {
        PLOG(ERROR) << "WriteFileDescriptor failed.";
        break;
      }
    }
  }
}
