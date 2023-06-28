// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LOGIN_MANAGER_FAKE_SECRET_UTIL_H_
#define LOGIN_MANAGER_FAKE_SECRET_UTIL_H_

#include <map>
#include <vector>
#include <stdint.h>

#include <base/files/scoped_file.h>

#include "login_manager/secret_util.h"

namespace login_manager {
namespace secret_util {

// Implements shared memory operations in a way that is valid within one process
// for testing. Production implementation can't be used because it might fail on
// development and testing Linux (non-ChromeOS) machines, depending on /dev/shm
// permissions.
class FakeSharedMemoryUtil : public SharedMemoryUtil {
 public:
  // |SharedMemoryUtil| implementation.
  base::ScopedFD WriteDataToSharedMemory(
      const std::vector<uint8_t>& data) override;
  bool ReadDataFromSharedMemory(const base::ScopedFD& in_data_fd,
                                size_t data_size,
                                std::vector<uint8_t>* out_data) override;

 private:
  std::map<int, std::vector<uint8_t>> data_;
};

}  // namespace secret_util
}  // namespace login_manager

#endif  // LOGIN_MANAGER_FAKE_SECRET_UTIL_H_
