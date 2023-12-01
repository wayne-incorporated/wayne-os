// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef TPM_MANAGER_SERVER_TPM_MANAGER_METRICS_H_
#define TPM_MANAGER_SERVER_TPM_MANAGER_METRICS_H_

#include <base/time/time.h>
#include <metrics/metrics_library.h>

#include "tpm_manager/server/dictionary_attack_reset_status.h"
#include "tpm_manager/server/tpm_status.h"

namespace tpm_manager {

struct SecretStatus {
  bool has_owner_password = false;
  bool has_endorsement_password = false;
  bool has_lockout_password = false;
  bool has_owner_delegate = false;
  bool has_reset_lock_permissions = false;
};

// The TPM Power wash result. These values are persisted to logs. Entries should
// not be renumbered and numeric values should never be reused. Please keep in
// sync with "TPMPowerWashResult" in tools/metrics/histograms/enums.xml in the
// Chromium repo.
enum class TPMPowerWashResult {
  kTPMClearSuccess = 0,
  kTPMClearFailed = 1,
  kMaxValue = kTPMClearFailed,
};

// The result of TPM ownership process. These values are persisted to logs.
// Entries should not be renumbered and numeric values should never be reused.
// Please keep in sync with "TPMTakeOwnershipResult" in
// tools/metrics/histograms/enums.xml in the Chromium repo.
enum class TPMTakeOwnershipResult {
  kSuccess = 0,
  kFailed = 1,
  kMaxValue = kFailed,
};

// This class provides wrapping functions for callers to report DA-related
// metrics without bothering to know all the constant declarations.
class TpmManagerMetrics : private MetricsLibrary {
 public:
  TpmManagerMetrics() = default;
  TpmManagerMetrics(const TpmManagerMetrics&) = delete;
  TpmManagerMetrics& operator=(const TpmManagerMetrics&) = delete;

  virtual ~TpmManagerMetrics() = default;

  virtual void ReportDictionaryAttackResetStatus(
      DictionaryAttackResetStatus status);

  virtual void ReportDictionaryAttackCounter(int counter);

  virtual void ReportSecretStatus(const SecretStatus& status);

  // Reports the TPM version fingerprint to the
  // "Platform.TPM.VersionFingerprint" histogram.
  virtual void ReportVersionFingerprint(int fingerprint);

  virtual void ReportTimeToTakeOwnership(base::TimeDelta elapsed_time);

  virtual void ReportAlertsData(const TpmStatus::AlertsData& alerts);

  virtual void ReportPowerWashResult(TPMPowerWashResult result);

  virtual void ReportTakeOwnershipResult(TPMTakeOwnershipResult result);

  virtual void ReportFilesystemUtilization(uint32_t size);

  virtual void ReportFilesystemInitTime(uint32_t time);

  virtual void ReportApRoVerificationTime(uint32_t time);

  virtual void ReportExpApRoVerificationStatus(uint32_t status);

  void set_metrics_library_for_testing(
      MetricsLibraryInterface* metrics_library) {
    metrics_library_ = metrics_library;
  }

 private:
  MetricsLibraryInterface* metrics_library_{this};
};

}  // namespace tpm_manager

#endif  // TPM_MANAGER_SERVER_TPM_MANAGER_METRICS_H_
