// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/utils/pipe_utils.h"

#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <string>

#include <base/logging.h>

#include "runtime_probe/system/context.h"

namespace runtime_probe {

namespace {

enum class PipeState {
  PENDING,
  ERROR,
  DONE,
};

// The system-defined size of buffer used to read from a pipe.
constexpr size_t kBufferSize = PIPE_BUF;

// Seconds to wait for runtime_probe helper to send probe results.
constexpr time_t kWaitSeconds = 5;

PipeState ReadPipe(int src_fd, std::string* dst_str) {
  char buffer[kBufferSize];
  const ssize_t bytes_read =
      Context::Get()->syscaller()->Read(src_fd, buffer, kBufferSize);
  if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    PLOG(ERROR) << "read() from fd " << src_fd << " failed";
    return PipeState::ERROR;
  }
  if (bytes_read == 0) {
    return PipeState::DONE;
  }
  if (bytes_read > 0) {
    dst_str->append(buffer, bytes_read);
  }
  return PipeState::PENDING;
}

}  // namespace

bool ReadNonblockingPipeToString(const std::vector<int>& fds,
                                 std::vector<std::string>* out) {
  struct timeval timeout;

  timeout.tv_sec = kWaitSeconds;
  timeout.tv_usec = 0;

  *out = std::vector<std::string>(fds.size(), "");
  std::vector<bool> done_array(fds.size(), false);

  while (true) {
    // This argument should be set to the highest-numbered file descriptor,
    // plus 1.
    fd_set read_fds;
    int nfds = 0;
    bool done = true;
    FD_ZERO(&read_fds);
    for (int i = 0; i < fds.size(); ++i) {
      if (!done_array[i]) {
        done = false;
        FD_SET(fds[i], &read_fds);
        nfds = std::max(nfds, fds[i] + 1);
      }
    }
    if (done)
      return true;

    int retval = Context::Get()->syscaller()->Select(nfds, &read_fds, nullptr,
                                                     nullptr, &timeout);
    if (retval < 0) {
      PLOG(ERROR) << "select() failed from runtime_probe_helper";
      return false;
    }

    // Should only happen on timeout. Log a warning here, so we get at least a
    // log if the process is stale.
    if (retval == 0) {
      LOG(WARNING) << "select() timed out. Process might be stale.";
      return false;
    }

    for (int i = 0; i < fds.size(); ++i) {
      if (!FD_ISSET(fds[i], &read_fds))
        continue;
      PipeState state = ReadPipe(fds[i], &out->at(i));
      if (state == PipeState::ERROR)
        return false;
      if (state == PipeState::DONE)
        done_array[i] = true;
    }
  }
}

}  // namespace runtime_probe
