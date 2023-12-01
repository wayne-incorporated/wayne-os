// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_ADD_ENTROPY_COMMAND_H_
#define LIBEC_ADD_ENTROPY_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command_async.h"

namespace ec {

class BRILLO_EXPORT AddEntropyCommand
    : public EcCommandAsync<struct ec_params_rollback_add_entropy, EmptyParam> {
 public:
  explicit AddEntropyCommand(bool reset);
  ~AddEntropyCommand() override = default;
};

static_assert(!std::is_copy_constructible<AddEntropyCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<AddEntropyCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_ADD_ENTROPY_COMMAND_H_
