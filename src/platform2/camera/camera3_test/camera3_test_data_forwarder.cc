// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "camera3_test/camera3_test_data_forwarder.h"

#include <memory>

#include <base/files/file_util.h>

namespace camera3_test {

void Camera3TestDataForwarder::SetData(const uint8_t* Data, size_t Size) {
  fuzz_data_ = const_cast<uint8_t*>(Data);
  data_size_ = Size;
}

void Camera3TestDataForwarder::GetData(uint8_t** Data, size_t* Size) {
  *Data = fuzz_data_;
  *Size = data_size_;
}

// static
Camera3TestDataForwarder* Camera3TestDataForwarder::GetInstance() {
  static Camera3TestDataForwarder forwarder;
  return &forwarder;
}

}  // namespace camera3_test
