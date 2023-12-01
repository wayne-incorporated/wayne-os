// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "vtpm/commands/unsupported_command.h"

#include <string>
#include <utility>

#include <base/functional/callback.h>
#include <base/logging.h>
#include <trunks/response_serializer.h>
#include <trunks/tpm_generated.h>

namespace vtpm {

UnsupportedCommand::UnsupportedCommand(trunks::ResponseSerializer* serializer)
    : response_serializer_(serializer) {
  CHECK(serializer);
}

void UnsupportedCommand::Run(const std::string& command,
                             CommandResponseCallback callback) {
  std::string response;
  response_serializer_->SerializeHeaderOnlyResponse(trunks::TPM_RC_COMMAND_CODE,
                                                    &response);
  std::move(callback).Run(response);
}

}  // namespace vtpm
