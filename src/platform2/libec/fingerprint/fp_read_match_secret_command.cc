// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "libec/fingerprint/fp_read_match_secret_command.h"

#include <optional>

namespace ec {

FpReadMatchSecretCommand::~FpReadMatchSecretCommand() {
  ClearSecretBuffer();
}

std::optional<brillo::SecureVector> FpReadMatchSecretCommand::Secret() {
  if (!secret_is_valid_) {
    return std::nullopt;
  }

  brillo::SecureVector secret(sizeof(Resp()->positive_match_secret));
  std::copy(
      Resp()->positive_match_secret,
      Resp()->positive_match_secret + sizeof(Resp()->positive_match_secret),
      secret.begin());
  ClearSecretBuffer();
  return secret;
}

void FpReadMatchSecretCommand::ClearSecretBuffer() {
  brillo::SecureClearContainer(Resp()->positive_match_secret);
  secret_is_valid_ = false;
}

bool FpReadMatchSecretCommand::Run(int fd) {
  secret_is_valid_ = EcCommandRun(fd);
  return secret_is_valid_;
}

bool FpReadMatchSecretCommand::EcCommandRun(int fd) {
  return EcCommand::Run(fd);
}

}  // namespace ec
