// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "kerberos/platform_helper.h"

#include <unistd.h>

#include <algorithm>
#include <optional>
#include <string>

#include <base/files/file_util.h>
#include <base/logging.h>

namespace kerberos {

namespace {

// Size limit on the total number of bytes to read from a pipe.
const size_t kMaxReadSize = 16 * 1024 * 1024;  // 16 MB

// The size of the buffer used to read from a pipe.
const size_t kBufferSize = PIPE_BUF;  // ~4 Kb on my system

}  // namespace

std::optional<std::string> ReadPipeToString(int fd) {
  std::string data;
  char buffer[kBufferSize];
  size_t total_read = 0;
  while (total_read < kMaxReadSize) {
    const ssize_t bytes_read = HANDLE_EINTR(
        read(fd, buffer, std::min(kBufferSize, kMaxReadSize - total_read)));
    if (bytes_read < 0)
      return std::nullopt;
    if (bytes_read == 0)
      return data;
    total_read += bytes_read;
    data.append(buffer, bytes_read);
  }

  // Size limit hit. Do one more read to check if the file size is exactly
  // kMaxReadSize bytes.
  if (HANDLE_EINTR(read(fd, buffer, 1)) != 0)
    return std::nullopt;
  return data;
}

base::ScopedFD WriteStringToPipe(const std::string& str) {
  int pipe_fd[2];
  if (!base::CreateLocalNonBlockingPipe(pipe_fd)) {
    LOG(ERROR) << "Failed to create pipe";
    return base::ScopedFD();
  }
  base::ScopedFD pipe_read_end(pipe_fd[0]);
  base::ScopedFD pipe_write_end(pipe_fd[1]);
  if (!base::WriteFileDescriptor(pipe_write_end.get(), str)) {
    LOG(ERROR) << "Failed to write string to pipe";
    return base::ScopedFD();
  }
  return pipe_read_end;
}

}  // namespace kerberos
