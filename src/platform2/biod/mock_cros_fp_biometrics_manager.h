// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_MOCK_CROS_FP_BIOMETRICS_MANAGER_H_
#define BIOD_MOCK_CROS_FP_BIOMETRICS_MANAGER_H_

#include <memory>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include <gmock/gmock.h>

#include "biod/cros_fp_biometrics_manager.h"
#include "biod/mock_biod_metrics.h"
#include "biod/power_button_filter.h"

namespace biod {

class MockCrosFpBiometricsManager : public CrosFpBiometricsManager {
 public:
  using CrosFpBiometricsManager::CrosFpBiometricsManager;
  ~MockCrosFpBiometricsManager() override = default;

  MOCK_METHOD(BiometricType, GetType, (), (override));
  MOCK_METHOD(BiometricsManager::EnrollSession,
              StartEnrollSession,
              (std::string user_id, std::string label),
              (override));
  MOCK_METHOD(BiometricsManager::AuthSession, StartAuthSession, (), (override));
  MOCK_METHOD(std::vector<std::unique_ptr<BiometricsManagerRecord>>,
              GetLoadedRecords,
              (),
              (override));
  MOCK_METHOD(bool, DestroyAllRecords, (), (override));
  MOCK_METHOD(void, RemoveRecordsFromMemory, (), (override));
  MOCK_METHOD(void,
              ScheduleMaintenance,
              (const base::TimeDelta& delta),
              (override));
  MOCK_METHOD(bool,
              ReadRecordsForSingleUser,
              (const std::string& user_id),
              (override));
  MOCK_METHOD(
      void,
      SetEnrollScanDoneHandler,
      (const BiometricsManager::EnrollScanDoneCallback& on_enroll_scan_done),
      (override));
  MOCK_METHOD(
      void,
      SetAuthScanDoneHandler,
      (const BiometricsManager::AuthScanDoneCallback& on_auth_scan_done),
      (override));
  MOCK_METHOD(
      void,
      SetSessionFailedHandler,
      (const BiometricsManager::SessionFailedCallback& on_session_failed),
      (override));
  MOCK_METHOD(bool, SendStatsOnLogin, (), (override));
  MOCK_METHOD(void, SetDiskAccesses, (bool allow), (override));
  MOCK_METHOD(bool, ResetSensor, (), (override));
  MOCK_METHOD(bool, ResetEntropy, (bool factory_init), (override));
  MOCK_METHOD(void, EndEnrollSession, (), (override));
  MOCK_METHOD(void, EndAuthSession, (), (override));
  MOCK_METHOD(void, OnMaintenanceTimerFired, (), (override));
  MOCK_METHOD(std::optional<BiodStorageInterface::RecordMetadata>,
              GetRecordMetadata,
              (const std::string& record_id),
              (const, override));
  MOCK_METHOD(std::optional<std::string>,
              GetLoadedRecordId,
              (int id),
              (override));

  // Delegate to the real implementation in the base class:
  // https://github.com/google/googletest/blob/HEAD/googlemock/docs/cook_book.md#delegating-calls-to-a-parent-class
  void OnMaintenanceTimerFiredDelegate() {
    CrosFpBiometricsManager::OnMaintenanceTimerFired();
  }
  // Expose protected methods for testing
  using CrosFpBiometricsManager::GetDirtyList;
  using CrosFpBiometricsManager::LoadRecord;
  using CrosFpBiometricsManager::UpdateTemplatesOnDisk;
};

}  // namespace biod

#endif  // BIOD_MOCK_CROS_FP_BIOMETRICS_MANAGER_H_
