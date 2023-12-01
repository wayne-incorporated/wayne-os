// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef BIOD_MOCK_BIOMETRICS_MANAGER_H_
#define BIOD_MOCK_BIOMETRICS_MANAGER_H_

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>

#include "biod/biometrics_manager.h"

namespace biod {

using testing::Return;

class MockBiometricsManager : public BiometricsManager {
 public:
  MockBiometricsManager() : session_weak_factory_(this) {}
  ~MockBiometricsManager() override = default;

  MOCK_METHOD(BiometricType, GetType, (), (override));
  MOCK_METHOD(EnrollSession,
              StartEnrollSession,
              (std::string user_id, std::string label),
              (override));
  MOCK_METHOD(AuthSession, StartAuthSession, (), (override));
  MOCK_METHOD(std::vector<std::unique_ptr<BiometricsManagerRecord>>,
              GetLoadedRecords,
              (),
              (override));
  MOCK_METHOD(bool, DestroyAllRecords, (), (override));
  MOCK_METHOD(void, RemoveRecordsFromMemory, (), (override));
  MOCK_METHOD(bool,
              ReadRecordsForSingleUser,
              (const std::string& user_id),
              (override));
  MOCK_METHOD(void,
              SetEnrollScanDoneHandler,
              (const EnrollScanDoneCallback& on_enroll_scan_done),
              (override));
  MOCK_METHOD(void,
              SetAuthScanDoneHandler,
              (const AuthScanDoneCallback& on_auth_scan_done),
              (override));
  MOCK_METHOD(void,
              SetSessionFailedHandler,
              (const SessionFailedCallback& on_session_failed),
              (override));
  MOCK_METHOD(bool, SendStatsOnLogin, (), (override));
  MOCK_METHOD(void, SetDiskAccesses, (bool allow), (override));
  MOCK_METHOD(bool, ResetSensor, (), (override));
  MOCK_METHOD(bool, ResetEntropy, (bool factory_init), (override));
  MOCK_METHOD(void, EndEnrollSession, (), (override));
  MOCK_METHOD(void, EndAuthSession, (), (override));
  MOCK_METHOD(void,
              ScheduleMaintenance,
              (const base::TimeDelta& delta),
              (override));

  base::WeakPtrFactory<MockBiometricsManager> session_weak_factory_;
};

}  //  namespace biod

#endif  // BIOD_MOCK_BIOMETRICS_MANAGER_H_
