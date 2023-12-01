// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/get_protocol_info_command.h"

namespace ec {

uint16_t GetProtocolInfoCommand::MaxReadBytes() const {
  return Resp()->max_response_packet_size - sizeof(struct ec_host_response);
}

uint16_t GetProtocolInfoCommand::MaxWriteBytes() const {
  // TODO(vpalatin): workaround for b/78544921, can be removed if MCU is fixed.
  return Resp()->max_request_packet_size - sizeof(struct ec_host_request) - 4;
}

}  // namespace ec
