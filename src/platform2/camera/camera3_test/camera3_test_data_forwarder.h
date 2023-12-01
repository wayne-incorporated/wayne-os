// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_TEST_DATA_FORWARDER_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_TEST_DATA_FORWARDER_H_

#include <stdint.h>

#include <base/synchronization/lock.h>

namespace camera3_test {
class Camera3TestDataForwarder {
 public:
  // Get Forwarder single instance
  static Camera3TestDataForwarder* GetInstance();

  void SetData(const uint8_t* Data, size_t Size);

  void GetData(uint8_t** Data, size_t* Size);

 private:
  uint8_t* fuzz_data_;
  size_t data_size_;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_TEST_DATA_FORWARDER_H_
