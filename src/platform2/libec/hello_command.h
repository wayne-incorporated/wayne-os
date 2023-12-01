// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_HELLO_COMMAND_H_
#define LIBEC_HELLO_COMMAND_H_

#include <brillo/brillo_export.h>
#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT HelloCommand
    : public EcCommand<struct ec_params_hello, struct ec_response_hello> {
 public:
  explicit HelloCommand(uint32_t data);
  ~HelloCommand() override = default;

  uint32_t GetResponseData() const;
};

static_assert(!std::is_copy_constructible<HelloCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<HelloCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_HELLO_COMMAND_H_
