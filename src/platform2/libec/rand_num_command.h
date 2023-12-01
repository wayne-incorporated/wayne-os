// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_RAND_NUM_COMMAND_H_
#define LIBEC_RAND_NUM_COMMAND_H_

#include <brillo/brillo_export.h>

#include "libec/ec_command.h"
#include "libec/rand_num_params.h"

namespace ec {

class BRILLO_EXPORT RandNumCommand
    : public EcCommand<struct ec_params_rand_num, struct rand::RandNumResp> {
 public:
  explicit RandNumCommand(uint16_t num_rand_bytes);
  ~RandNumCommand() override = default;

  rand::RandNumData GetRandNumData() const;
};

static_assert(!std::is_copy_constructible<RandNumCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<RandNumCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec
#endif  // LIBEC_RAND_NUM_COMMAND_H_
