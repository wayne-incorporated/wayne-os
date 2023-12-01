// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/*
 * Retry device handler.
 */
#include "hps/hal/retry.h"

#include <iostream>

#include <base/threading/thread.h>

namespace hps {

bool RetryDev::ReadDevice(uint8_t cmd, uint8_t* data, size_t len) {
  for (int i = 0; i < this->retries_; i++) {
    if (device_->Read(cmd, data, len)) {
      // Success!
      return true;
    }
    base::PlatformThread::Sleep(this->delay_);
  }
  return false;
}

bool RetryDev::WriteDevice(uint8_t cmd, const uint8_t* data, size_t len) {
  for (int i = 0; i < this->retries_; i++) {
    if (device_->Write(cmd, data, len)) {
      // Success!
      return true;
    }
    base::PlatformThread::Sleep(this->delay_);
  }
  return false;
}

}  // namespace hps
