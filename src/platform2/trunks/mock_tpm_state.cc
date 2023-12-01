// Copyright 2014 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/mock_tpm_state.h"

#include <gmock/gmock.h>

using testing::Return;

namespace trunks {

MockTpmState::MockTpmState() {
  ON_CALL(*this, IsOwnerPasswordSet()).WillByDefault(Return(true));
  ON_CALL(*this, IsEndorsementPasswordSet()).WillByDefault(Return(true));
  ON_CALL(*this, IsLockoutPasswordSet()).WillByDefault(Return(true));
  ON_CALL(*this, IsOwned()).WillByDefault(Return(true));
  ON_CALL(*this, IsPlatformHierarchyEnabled()).WillByDefault(Return(true));
  ON_CALL(*this, IsStorageHierarchyEnabled()).WillByDefault(Return(true));
  ON_CALL(*this, IsEndorsementHierarchyEnabled()).WillByDefault(Return(true));
  ON_CALL(*this, IsEnabled()).WillByDefault(Return(true));
  ON_CALL(*this, WasShutdownOrderly()).WillByDefault(Return(true));
  ON_CALL(*this, IsRSASupported()).WillByDefault(Return(true));
  ON_CALL(*this, IsECCSupported()).WillByDefault(Return(true));
  ON_CALL(*this, GetLockoutCounter()).WillByDefault(Return(0));
  ON_CALL(*this, GetLockoutThreshold()).WillByDefault(Return(0));
  ON_CALL(*this, GetLockoutInterval()).WillByDefault(Return(0));
  ON_CALL(*this, GetLockoutRecovery()).WillByDefault(Return(0));
  ON_CALL(*this, GetMaxNVSize()).WillByDefault(Return(2048));
}

MockTpmState::~MockTpmState() {}

}  // namespace trunks
