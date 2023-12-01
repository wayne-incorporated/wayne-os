// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_SYSTEM_SYSCALLER_IMPL_H_
#define RUNTIME_PROBE_SYSTEM_SYSCALLER_IMPL_H_

#include <sys/select.h>
#include <unistd.h>

#include "runtime_probe/system/syscaller.h"

namespace runtime_probe {

class SyscallerImpl : public Syscaller {
 public:
  ~SyscallerImpl() override;
  ssize_t Read(int fd, void* buf, size_t nbytes) override;
  int Select(int nfds,
             fd_set* readfds,
             fd_set* writefds,
             fd_set* exceptfds,
             struct timeval* timeout) override;
  int Ioctl(int fd,
            unsigned long request,  // NOLINT(runtime/int)
            int data) override;
  int Ioctl(int fd,
            unsigned long request,  // NOLINT(runtime/int)
            void* data) override;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_SYSTEM_SYSCALLER_IMPL_H_
