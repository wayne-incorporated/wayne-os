// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mock_cryptohome_keys_manager.h"

using testing::_;
using testing::Return;

namespace cryptohome {

MockCryptohomeKeysManager::MockCryptohomeKeysManager()
    : CryptohomeKeysManager() {
  ON_CALL(*this, Init()).WillByDefault(Return());
  ON_CALL(*this, HasAnyCryptohomeKey()).WillByDefault(Return(true));
  ON_CALL(*this, GetKeyLoader(_))
      .WillByDefault(Return(&mock_cryptohome_key_loader_));
}

}  // namespace cryptohome
