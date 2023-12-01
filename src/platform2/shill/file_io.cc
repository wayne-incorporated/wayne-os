// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/file_io.h"

#include <fcntl.h>
#include <unistd.h>

#include <base/posix/eintr_wrapper.h>

namespace shill {

FileIO::FileIO() = default;

FileIO::~FileIO() = default;

// static
FileIO* FileIO::GetInstance() {
  static base::NoDestructor<FileIO> instance;
  return instance.get();
}

ssize_t FileIO::Write(int fd, const void* buf, size_t count) {
  return HANDLE_EINTR(write(fd, buf, count));
}

ssize_t FileIO::Read(int fd, void* buf, size_t count) {
  return HANDLE_EINTR(read(fd, buf, count));
}

int FileIO::Close(int fd) {
  return IGNORE_EINTR(close(fd));
}

int FileIO::SetFdNonBlocking(int fd) {
  const int flags = HANDLE_EINTR(fcntl(fd, F_GETFL)) | O_NONBLOCK;
  return HANDLE_EINTR(fcntl(fd, F_SETFL, flags));
}

}  // namespace shill
