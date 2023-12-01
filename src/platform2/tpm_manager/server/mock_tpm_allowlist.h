// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_TPM_ALLOWLIST_H_
#define TPM_MANAGER_SERVER_MOCK_TPM_ALLOWLIST_H_

#include "tpm_manager/server/tpm_allowlist.h"

#include <gmock/gmock.h>

namespace tpm_manager {

class MockTpmAllowlist : public TpmAllowlist {
 public:
  MockTpmAllowlist() = default;
  ~MockTpmAllowlist() override = default;

  MOCK_METHOD(bool, IsAllowed, (), (override));
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_TPM_ALLOWLIST_H_
