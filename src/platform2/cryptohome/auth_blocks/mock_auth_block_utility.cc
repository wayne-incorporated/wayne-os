// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/auth_blocks/mock_auth_block_utility.h"

namespace cryptohome {

namespace {

using ::cryptohome::error::CryptohomeError;
using ::hwsec_foundation::status::OkStatus;
using ::testing::_;

}  // namespace

MockAuthBlockUtility::MockAuthBlockUtility() {
  ON_CALL(*this, PrepareAuthBlockForRemoval(_, _))
      .WillByDefault([&](const AuthBlockState& auth_state,
                         AuthBlockUtility::CryptohomeStatusCallback callback) {
        std::move(callback).Run(OkStatus<CryptohomeError>());
      });
}

}  // namespace cryptohome
