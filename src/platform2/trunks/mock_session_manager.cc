// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "trunks/mock_session_manager.h"

#include "trunks/tpm_generated.h"

namespace trunks {

MockSessionManager::MockSessionManager() {
  ON_CALL(*this, GetSessionHandle())
      .WillByDefault(testing::Return(TPM_RH_FIRST));
}

MockSessionManager::~MockSessionManager() {}

}  // namespace trunks
