// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_GET_PROTOCOL_INFO_COMMAND_H_
#define LIBEC_GET_PROTOCOL_INFO_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT GetProtocolInfoCommand
    : public EcCommand<EmptyParam, struct ec_response_get_protocol_info> {
 public:
  GetProtocolInfoCommand() : EcCommand(EC_CMD_GET_PROTOCOL_INFO) {}
  ~GetProtocolInfoCommand() override = default;

  uint16_t MaxReadBytes() const;
  uint16_t MaxWriteBytes() const;
};

static_assert(!std::is_copy_constructible<GetProtocolInfoCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<GetProtocolInfoCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_GET_PROTOCOL_INFO_COMMAND_H_
