// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_MOCK_TPM_MANAGER_METRICS_H_
#define TPM_MANAGER_SERVER_MOCK_TPM_MANAGER_METRICS_H_

#include "tpm_manager/server/tpm_manager_metrics.h"

namespace tpm_manager {

class MockTpmManagerMetrics : public TpmManagerMetrics {
 public:
  MockTpmManagerMetrics() = default;
  virtual ~MockTpmManagerMetrics() = default;

  MOCK_METHOD(void,
              ReportDictionaryAttackResetStatus,
              (DictionaryAttackResetStatus),
              (override));

  MOCK_METHOD(void, ReportDictionaryAttackCounter, (int), (override));
  MOCK_METHOD(void, ReportVersionFingerprint, (int), (override));
  MOCK_METHOD(void, ReportTimeToTakeOwnership, (base::TimeDelta), (override));
  MOCK_METHOD(void, ReportSecretStatus, (const SecretStatus&), (override));
  MOCK_METHOD(void,
              ReportAlertsData,
              (const TpmStatus::AlertsData&),
              (override));
  MOCK_METHOD(void, ReportPowerWashResult, (TPMPowerWashResult), (override));
  MOCK_METHOD(void,
              ReportTakeOwnershipResult,
              (TPMTakeOwnershipResult),
              (override));
  MOCK_METHOD(void, ReportFilesystemUtilization, (uint32_t), (override));
  MOCK_METHOD(void, ReportFilesystemInitTime, (uint32_t), (override));
  MOCK_METHOD(void, ReportApRoVerificationTime, (uint32_t), (override));
  MOCK_METHOD(void, ReportExpApRoVerificationStatus, (uint32_t), (override));
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_MOCK_TPM_MANAGER_METRICS_H_
