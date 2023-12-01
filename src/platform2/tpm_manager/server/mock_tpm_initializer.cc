// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "tpm_manager/server/mock_tpm_initializer.h"

using testing::_;
using testing::DoAll;
using testing::Return;
using testing::SetArgPointee;

namespace tpm_manager {

MockTpmInitializer::MockTpmInitializer() {
  ON_CALL(*this, PreInitializeTpm()).WillByDefault(Return(true));
  ON_CALL(*this, InitializeTpm(_))
      .WillByDefault(DoAll(SetArgPointee<0>(false), Return(true)));
  ON_CALL(*this, EnsurePersistentOwnerDelegate()).WillByDefault(Return(true));
  ON_CALL(*this, ResetDictionaryAttackLock())
      .WillByDefault(
          Return(DictionaryAttackResetStatus::kResetAttemptSucceeded));
  ON_CALL(*this, DisableDictionaryAttackMitigation())
      .WillByDefault(Return(TpmInitializerStatus::kSuccess));
  ON_CALL(*this, ChangeOwnerPassword(_, _)).WillByDefault(Return(true));
}
MockTpmInitializer::~MockTpmInitializer() {}

}  // namespace tpm_manager
