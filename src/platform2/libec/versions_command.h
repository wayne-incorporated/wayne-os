// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_VERSIONS_COMMAND_H_
#define LIBEC_VERSIONS_COMMAND_H_

#include <array>
#include <vector>

#include <brillo/secure_blob.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT VersionsCommand
    : public EcCommand<struct ec_params_get_cmd_versions_v1,
                       struct ec_response_get_cmd_versions> {
 public:
  explicit VersionsCommand(uint16_t command_code)
      : EcCommand(EC_CMD_GET_CMD_VERSIONS, kVersionOne) {
    Req()->cmd = command_code;
  }
  ~VersionsCommand() override = default;

  uint16_t CommandCode() const { return Req()->cmd; }
  EcCmdVersionSupportStatus IsVersionSupported(uint32_t version);
};

static_assert(!std::is_copy_constructible<VersionsCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<VersionsCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_VERSIONS_COMMAND_H_
