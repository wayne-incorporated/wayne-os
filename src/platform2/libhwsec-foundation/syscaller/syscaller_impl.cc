// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libhwsec-foundation/syscaller/syscaller_impl.h"

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>

#include <base/posix/eintr_wrapper.h>

namespace hwsec_foundation {

int SyscallerImpl::Open(const char* pathname, int flags) {
  return HANDLE_EINTR(open(pathname, flags));
}

int SyscallerImpl::Close(int fd) {
  return close(fd);
}

ssize_t SyscallerImpl::Write(int fd, const void* buf, size_t count) {
  return HANDLE_EINTR(write(fd, buf, count));
}

ssize_t SyscallerImpl::Read(int fd, void* buf, size_t count) {
  return HANDLE_EINTR(read(fd, buf, count));
}

int SyscallerImpl::Select(int nfds,
                          fd_set* readfds,
                          fd_set* writefds,
                          fd_set* exceptfds,
                          struct timeval* timeout) {
  return HANDLE_EINTR(select(nfds, readfds, writefds, exceptfds, timeout));
}

int SyscallerImpl::Ioctl(int fd,
                         unsigned long request,  // NOLINT(runtime/int)
                         struct mei_connect_client_data* data) {
  return ioctl(fd, request, data);
}

}  // namespace hwsec_foundation
