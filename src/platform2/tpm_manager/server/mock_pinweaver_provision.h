// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_PINWEAVER_PROVISION_H_
#define TPM_MANAGER_SERVER_MOCK_PINWEAVER_PROVISION_H_

#include "tpm_manager/server/pinweaver_provision.h"

#include <gmock/gmock.h>

namespace tpm_manager {

class MockPinWeaverProvision : public PinWeaverProvision {
 public:
  MockPinWeaverProvision() = default;
  ~MockPinWeaverProvision() override = default;
  MOCK_METHOD(bool, Provision, (), (override));
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_PINWEAVER_PROVISION_H_
