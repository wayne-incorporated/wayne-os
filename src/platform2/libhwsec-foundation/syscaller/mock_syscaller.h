// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBHWSEC_FOUNDATION_SYSCALLER_MOCK_SYSCALLER_H_
#define LIBHWSEC_FOUNDATION_SYSCALLER_MOCK_SYSCALLER_H_

#include "libhwsec-foundation/hwsec-foundation_export.h"
#include "libhwsec-foundation/syscaller/syscaller.h"

namespace hwsec_foundation {

class HWSEC_FOUNDATION_EXPORT MockSyscaller : public Syscaller {
 public:
  MockSyscaller() = default;
  ~MockSyscaller() override = default;
  MOCK_METHOD(int, Open, (const char*, int), (override));
  MOCK_METHOD(int, Close, (int fd), (override));
  MOCK_METHOD(ssize_t, Write, (int, const void*, size_t), (override));
  MOCK_METHOD(ssize_t, Read, (int, void*, size_t), (override));
  MOCK_METHOD(int,
              Select,
              (int, fd_set*, fd_set*, fd_set*, struct timeval*),
              (override));
  MOCK_METHOD(int,
              Ioctl,
              (int,
               unsigned long,  // NOLINT(runtime/int)
               struct mei_connect_client_data*),
              (override));
};

}  // namespace hwsec_foundation

#endif  // LIBHWSEC_FOUNDATION_SYSCALLER_MOCK_SYSCALLER_H_
