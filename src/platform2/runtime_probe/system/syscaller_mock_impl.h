// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_SYSTEM_SYSCALLER_MOCK_IMPL_H_
#define RUNTIME_PROBE_SYSTEM_SYSCALLER_MOCK_IMPL_H_

#include <sys/select.h>
#include <unistd.h>

#include <gmock/gmock.h>

#include "runtime_probe/system/syscaller.h"

namespace runtime_probe {

class SyscallerMockImpl : public Syscaller {
 public:
  SyscallerMockImpl() = default;
  ~SyscallerMockImpl() override = default;
  MOCK_METHOD(ssize_t, Read, (int, void*, size_t), (override));
  MOCK_METHOD(int,
              Select,
              (int, fd_set*, fd_set*, fd_set*, struct timeval*),
              (override));
  MOCK_METHOD(int,
              Ioctl,
              (int, unsigned long, int),  // NOLINT(runtime/int)
              (override));
  MOCK_METHOD(int,
              Ioctl,
              (int, unsigned long, void*),  // NOLINT(runtime/int)
              (override));
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_SYSTEM_SYSCALLER_MOCK_IMPL_H_
