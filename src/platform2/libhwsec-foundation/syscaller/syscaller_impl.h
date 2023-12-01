// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_SYSCALLER_SYSCALLER_IMPL_H_
#define LIBHWSEC_FOUNDATION_SYSCALLER_SYSCALLER_IMPL_H_

#include "libhwsec-foundation/hwsec-foundation_export.h"
#include "libhwsec-foundation/syscaller/syscaller.h"

namespace hwsec_foundation {

class HWSEC_FOUNDATION_EXPORT SyscallerImpl : public Syscaller {
 public:
  SyscallerImpl() = default;
  ~SyscallerImpl() override = default;
  int Open(const char* pathname, int flags) override;
  int Close(int fd) override;
  ssize_t Write(int fd, const void* buf, size_t count) override;
  ssize_t Read(int fd, void* buf, size_t count) override;
  int Select(int nfds,
             fd_set* readfds,
             fd_set* writefds,
             fd_set* exceptfds,
             struct timeval* timeout) override;
  int Ioctl(int fd,
            unsigned long request,  // NOLINT(runtime/int)
            struct mei_connect_client_data* data) override;
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_SYSCALLER_SYSCALLER_IMPL_H_
