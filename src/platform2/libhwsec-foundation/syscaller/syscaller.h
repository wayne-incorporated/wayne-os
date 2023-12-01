// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_SYSCALLER_SYSCALLER_H_
#define LIBHWSEC_FOUNDATION_SYSCALLER_SYSCALLER_H_

#include <fcntl.h>
#include <linux/mei.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <unistd.h>

#include "libhwsec-foundation/hwsec-foundation_export.h"
#include "libhwsec-foundation/signature_traits.h"

namespace hwsec_foundation {

class HWSEC_FOUNDATION_EXPORT Syscaller {
 public:
  virtual ~Syscaller() = default;
  virtual int Open(const char* pathname, int flags) = 0;
  virtual int Close(int fd) = 0;
  virtual ssize_t Write(int fd, const void* buf, size_t count) = 0;
  virtual ssize_t Read(int fd, void* buf, size_t count) = 0;
  virtual int Select(int nfds,
                     fd_set* readfds,
                     fd_set* writefds,
                     fd_set* exceptfds,
                     struct timeval* timeout) = 0;
  virtual int Ioctl(int fd,
                    unsigned long request,  // NOLINT(runtime/int)
                    mei_connect_client_data* data) = 0;
};

// In best effort, validate the function signature are declared correctly.
static_assert(is_same_signature_v<decltype(&Syscaller::Close), decltype(close)>,
              "`Syscaller::Close()` has different signature from `close()`");
static_assert(is_same_signature_v<decltype(&Syscaller::Write), decltype(write)>,
              "`Syscaller::Write()` has different signature from `write()`");
static_assert(is_same_signature_v<decltype(&Syscaller::Read), decltype(read)>,
              "`Syscaller::Read()` has different signature from `read()`");
static_assert(
    is_same_signature_v<decltype(&Syscaller::Select), decltype(select)>,
    "`Syscaller::Select()` has different signature from `select()`");

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_SYSCALLER_SYSCALLER_H_
