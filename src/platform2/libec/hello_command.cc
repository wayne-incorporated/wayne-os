// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/hello_command.h"

namespace ec {

HelloCommand::HelloCommand(uint32_t data) : EcCommand(EC_CMD_HELLO) {
  Req()->in_data = data;
}

uint32_t HelloCommand::GetResponseData() const {
  return Resp()->out_data;
}

}  // namespace ec
