// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_SYSTEM_SYSCALLER_H_
#define RUNTIME_PROBE_SYSTEM_SYSCALLER_H_

#include <sys/select.h>
#include <unistd.h>

namespace runtime_probe {

class Syscaller {
 public:
  Syscaller() = default;
  virtual ~Syscaller() = default;

  virtual ssize_t Read(int fd, void* buf, size_t nbytes) = 0;
  virtual int Select(int nfds,
                     fd_set* readfds,
                     fd_set* writefds,
                     fd_set* exceptfds,
                     struct timeval* timeout) = 0;
  virtual int Ioctl(int fd,
                    unsigned long request,  // NOLINT(runtime/int)
                    int data) = 0;
  virtual int Ioctl(int fd,
                    unsigned long request,  // NOLINT(runtime/int)
                    void* data) = 0;
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_SYSTEM_SYSCALLER_H_
