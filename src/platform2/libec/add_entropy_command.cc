// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/time/time.h>
#include "libec/add_entropy_command.h"

namespace ec {

AddEntropyCommand::AddEntropyCommand(bool reset)
    : EcCommandAsync(EC_CMD_ADD_ENTROPY,
                     ADD_ENTROPY_GET_RESULT,
                     {.poll_for_result_num_attempts = 20,
                      .poll_interval = base::Milliseconds(100),
                      // The EC temporarily stops responding to EC commands
                      // when this command is run, so we will keep trying until
                      // we get success (or time out).
                      .validate_poll_result = false},
                     0) {
  if (reset) {
    Req()->action = ADD_ENTROPY_RESET_ASYNC;
  } else {
    Req()->action = ADD_ENTROPY_ASYNC;
  }
}

}  // namespace ec
