// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_ENCRYPTION_STATUS_COMMAND_H_
#define LIBEC_FINGERPRINT_FP_ENCRYPTION_STATUS_COMMAND_H_

#include <brillo/brillo_export.h>
#include <string>

#include "libec/ec_command.h"

namespace ec {

class BRILLO_EXPORT FpEncryptionStatusCommand
    : public EcCommand<EmptyParam, struct ec_response_fp_encryption_status> {
 public:
  FpEncryptionStatusCommand();
  ~FpEncryptionStatusCommand() override = default;

  static std::string ParseFlags(uint32_t flags);

  uint32_t GetValidFlags() const;
  uint32_t GetStatus() const;
};

static_assert(!std::is_copy_constructible<FpEncryptionStatusCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<FpEncryptionStatusCommand>::value,
              "EcCommands are not copy-assignable by default");
}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_ENCRYPTION_STATUS_COMMAND_H_
