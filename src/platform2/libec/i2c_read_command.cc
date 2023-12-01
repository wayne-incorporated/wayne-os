// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/i2c_read_command.h"

#include <base/notreached.h>

namespace ec {

uint16_t I2cReadCommand::Data() const {
  CHECK(RespData().size() == read_len_)
      << "Unexpected response size. Expected " << read_len_ << ", got"
      << RespData().size() << ".";
  if (read_len_ == 1) {
    return RespData()[0];
  }
  if (read_len_ == 2) {
    return *reinterpret_cast<const uint16_t*>(RespData().data());
  }
  NOTREACHED();
  return 0;
}

}  // namespace ec
