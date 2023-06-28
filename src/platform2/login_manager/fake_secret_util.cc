// Copyright 2019 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "login_manager/fake_secret_util.h"

#include <fcntl.h>
#include <sys/types.h>

namespace login_manager {
namespace secret_util {

base::ScopedFD FakeSharedMemoryUtil::WriteDataToSharedMemory(
    const std::vector<uint8_t>& data) {
  // Return an invalid file descriptor if the input is empty to match
  // the behavior of base::SharedMemory::Create.
  if (data.empty()) {
    return base::ScopedFD();
  }

  base::ScopedFD fd(open("/dev/null", O_RDONLY));
  data_[fd.get()] = data;
  return fd;
}

bool FakeSharedMemoryUtil::ReadDataFromSharedMemory(
    const base::ScopedFD& in_data_fd,
    size_t data_size,
    std::vector<uint8_t>* out_data) {
  if (!data_.count(in_data_fd.get()))
    return false;
  *out_data = data_[in_data_fd.get()];
  return true;
}

}  // namespace secret_util
}  // namespace login_manager
