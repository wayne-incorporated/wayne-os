// Copyright 2015 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_TPM_STATUS_H_
#define TPM_MANAGER_SERVER_MOCK_TPM_STATUS_H_

#include "tpm_manager/server/tpm_status.h"

#include <vector>

#include <gmock/gmock.h>

namespace tpm_manager {

class MockTpmStatus : public TpmStatus {
 public:
  MockTpmStatus();
  ~MockTpmStatus() override;

  MOCK_METHOD(bool, IsTpmEnabled, (), (override));
  MOCK_METHOD(bool, GetTpmOwned, (TpmOwnershipStatus*), (override));
  MOCK_METHOD(bool,
              GetDictionaryAttackInfo,
              (uint32_t*, uint32_t*, bool*, uint32_t*),
              (override));
  MOCK_METHOD(bool, IsDictionaryAttackMitigationEnabled, (bool*), (override));
  MOCK_METHOD(bool,
              GetVersionInfo,
              (uint32_t*,
               uint64_t*,
               uint32_t*,
               uint32_t*,
               uint64_t*,
               std::vector<uint8_t>*),
              (override));
  MOCK_METHOD(void, MarkRandomOwnerPasswordSet, (), (override));
  MOCK_METHOD(bool, SupportU2f, (), (override));
  MOCK_METHOD(bool, SupportPinweaver, (), (override));
  MOCK_METHOD(GscVersion, GetGscVersion, (), (override));
  MOCK_METHOD(bool,
              GetRoVerificationStatus,
              (tpm_manager::RoVerificationStatus*),
              (override));
  MOCK_METHOD(bool, GetAlertsData, (AlertsData * alerts), (override));
  MOCK_METHOD(bool,
              GetTi50Stats,
              (uint32_t*, uint32_t*, uint32_t*, uint32_t*),
              (override));
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_TPM_STATUS_H_
