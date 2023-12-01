// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_FP_READ_MATCH_SECRET_COMMAND_H_
#define LIBEC_FINGERPRINT_FP_READ_MATCH_SECRET_COMMAND_H_

#include <optional>

#include <brillo/brillo_export.h>
#include <brillo/secure_blob.h>
#include "libec/ec_command.h"
#include "libec/fingerprint/fp_read_match_secret_command.h"

namespace ec {

class BRILLO_EXPORT FpReadMatchSecretCommand
    : public EcCommand<struct ec_params_fp_read_match_secret,
                       struct ec_response_fp_read_match_secret> {
 public:
  explicit FpReadMatchSecretCommand(uint16_t index)
      : EcCommand(EC_CMD_FP_READ_MATCH_SECRET) {
    Req()->fgr = index;
  }
  ~FpReadMatchSecretCommand() override;

  bool Run(int fd) override;

  std::optional<brillo::SecureVector> Secret();

 protected:
  void ClearSecretBuffer();
  virtual bool EcCommandRun(int fd);

 private:
  bool secret_is_valid_ = false;
};

static_assert(!std::is_copy_constructible<FpReadMatchSecretCommand>::value,
              "EcCommands are not copyable by default");
static_assert(!std::is_copy_assignable<FpReadMatchSecretCommand>::value,
              "EcCommands are not copy-assignable by default");

}  // namespace ec

#endif  // LIBEC_FINGERPRINT_FP_READ_MATCH_SECRET_COMMAND_H_
