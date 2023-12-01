// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/system/syscaller_impl.h"

#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>

#include "base/posix/eintr_wrapper.h"

namespace runtime_probe {

SyscallerImpl::~SyscallerImpl() = default;

ssize_t SyscallerImpl::Read(int fd, void* buf, size_t nbytes) {
  return HANDLE_EINTR(read(fd, buf, nbytes));
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
                         int data) {
  return ioctl(fd, request, data);
}

int SyscallerImpl::Ioctl(int fd,
                         unsigned long request,  // NOLINT(runtime/int)
                         void* data) {
  return ioctl(fd, request, data);
}

}  // namespace runtime_probe
