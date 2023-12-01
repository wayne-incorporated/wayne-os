// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cryptohome/mock_cryptohome_key_loader.h"

using testing::_;
using testing::Return;

namespace cryptohome {

namespace {

constexpr hwsec::Key kTestKey{.token = 17};

}  // namespace

MockCryptohomeKeyLoader::MockCryptohomeKeyLoader() : CryptohomeKeyLoader() {
  ON_CALL(*this, HasCryptohomeKey()).WillByDefault(Return(true));
  ON_CALL(*this, GetCryptohomeKey()).WillByDefault(Return(kTestKey));
  ON_CALL(*this, Init()).WillByDefault(Return());
}

MockCryptohomeKeyLoader::~MockCryptohomeKeyLoader() {}

}  // namespace cryptohome
