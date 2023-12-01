// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_POLICY_MOCK_DEVICE_POLICY_H_
#define LIBBRILLO_POLICY_MOCK_DEVICE_POLICY_H_

#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <gmock/gmock.h>

#include "policy/device_policy.h"

#pragma GCC visibility push(default)

namespace policy {

// This is a generic mock class for the DevicePolicy that can be used by other
// subsystems for tests. It allows to mock out the reading of a real policy
// file and to simulate different policy values.
// The test that needs policies would then do something like this :
// // Prepare the action that would return a predefined policy value:
// ACTION_P(SetMetricsPolicy, enabled) {
//   *arg0 = enabled;
//   return true;
// }
// ...
// // Initialize the Mock class
// policy::MockDevicePolicy* device_policy = new policy::MockDevicePolicy();
// // We should expect calls to LoadPolicy almost always and return true.
// EXPECT_CALL(*device_policy_, LoadPolicy())
//     .Times(AnyNumber())
//     .WillRepeatedly(Return(true));
// // This example needs to simulate the Metrics Enabled policy being set.
// EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
//     .Times(AnyNumber())
//     .WillRepeatedly(SetMetricsPolicy(true));
// policy::PolicyProvider provider(device_policy);
// ...
// // In a test that needs other value of that policy we can do that:
// EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
//     .WillOnce(SetMetricsPolicy(false));
//
// See metrics_library_test.cc for example.
class MockDevicePolicy : public DevicePolicy {
 public:
  MockDevicePolicy() {
    ON_CALL(*this, LoadPolicy(/*delete_invalid_files=*/testing::_))
        .WillByDefault(testing::Return(true));
  }
  ~MockDevicePolicy() override = default;

  MOCK_METHOD(bool, LoadPolicy, (bool), (override));
  MOCK_METHOD(bool, IsEnterpriseEnrolled, (), (const, override));

  MOCK_METHOD(bool, GetPolicyRefreshRate, (int*), (const, override));
  MOCK_METHOD(bool, GetGuestModeEnabled, (bool*), (const, override));
  MOCK_METHOD(bool, GetCameraEnabled, (bool*), (const, override));
  MOCK_METHOD(bool, GetShowUserNames, (bool*), (const, override));
  MOCK_METHOD(bool, GetDataRoamingEnabled, (bool*), (const, override));
  MOCK_METHOD(bool, GetAllowNewUsers, (bool*), (const, override));
  MOCK_METHOD(bool, GetMetricsEnabled, (bool*), (const, override));
  MOCK_METHOD(bool, GetReportVersionInfo, (bool*), (const, override));
  MOCK_METHOD(bool, GetReportActivityTimes, (bool*), (const, override));
  MOCK_METHOD(bool, GetReportBootMode, (bool*), (const, override));
  MOCK_METHOD(bool,
              GetEphemeralSettings,
              (EphemeralSettings*),
              (const, override));
  MOCK_METHOD(bool, GetReleaseChannel, (std::string*), (const, override));
  MOCK_METHOD(bool, GetReleaseChannelDelegated, (bool*), (const, override));
  MOCK_METHOD(bool, GetReleaseLtsTag, (std::string*), (const, override));
  MOCK_METHOD(bool, GetUpdateDisabled, (bool*), (const, override));
  MOCK_METHOD(bool, GetTargetVersionPrefix, (std::string*), (const, override));
  MOCK_METHOD(bool,
              GetTargetVersionSelector,
              (std::string*),
              (const, override));
  MOCK_METHOD(bool, GetRollbackToTargetVersion, (int*), (const, override));
  MOCK_METHOD(bool, GetRollbackAllowedMilestones, (int*), (const, override));
  MOCK_METHOD(bool, GetScatterFactorInSeconds, (int64_t*), (const, override));
  MOCK_METHOD(bool,
              GetAllowedConnectionTypesForUpdate,
              (std::set<std::string>*),
              (const, override));
  MOCK_METHOD(bool,
              GetOpenNetworkConfiguration,
              (std::string*),
              (const, override));
  MOCK_METHOD(bool, GetOwner, (std::string*), (const, override));
  MOCK_METHOD(bool, GetHttpDownloadsEnabled, (bool*), (const, override));
  MOCK_METHOD(bool, GetAuP2PEnabled, (bool*), (const, override));
  MOCK_METHOD(bool,
              GetAllowKioskAppControlChromeVersion,
              (bool*),
              (const, override));
  MOCK_METHOD(bool,
              GetUsbDetachableWhitelist,
              (std::vector<DevicePolicy::UsbDeviceId>*),
              (const, override));
  MOCK_METHOD(bool,
              GetAutoLaunchedKioskAppId,
              (std::string*),
              (const, override));
  MOCK_METHOD(bool, IsEnterpriseManaged, (), (const, override));
  MOCK_METHOD(bool,
              GetSecondFactorAuthenticationMode,
              (int*),
              (const, override));
  MOCK_METHOD(std::optional<bool>,
              GetRunAutomaticCleanupOnLogin,
              (),
              (const, override));
  MOCK_METHOD(bool,
              GetDisallowedTimeIntervals,
              (std::vector<WeeklyTimeInterval>*),
              (const, override));
  MOCK_METHOD(bool,
              GetDeviceUpdateStagingSchedule,
              (std::vector<DayPercentagePair>*),
              (const, override));
  MOCK_METHOD(bool,
              GetDeviceQuickFixBuildToken,
              (std::string*),
              (const, override));
  MOCK_METHOD(bool, GetDeviceDirectoryApiId, (std::string*), (const, override));
  MOCK_METHOD(bool, GetCustomerId, (std::string*), (const, override));
  MOCK_METHOD(bool, VerifyPolicySignature, (), (override));
  MOCK_METHOD(bool, GetChannelDowngradeBehavior, (int*), (const, override));
  MOCK_METHOD(bool,
              GetHighestDeviceMinimumVersion,
              (base::Version*),
              (const, override));
  MOCK_METHOD(bool,
              GetDeviceMarketSegment,
              (DeviceMarketSegment*),
              (const, override));
  MOCK_METHOD(bool,
              GetDeviceDebugPacketCaptureAllowed,
              (bool*),
              (const, override));
  MOCK_METHOD(bool,
              GetDeviceKeylockerForStorageEncryptionEnabled,
              (bool*),
              (const, override));
  MOCK_METHOD(std::optional<bool>,
              GetReportDeviceSecurityStatus,
              (),
              (const, override));
  MOCK_METHOD(std::optional<bool>,
              GetDeviceReportXDREvents,
              (),
              (const, override));
};
}  // namespace policy

#pragma GCC visibility pop

#endif  // LIBBRILLO_POLICY_MOCK_DEVICE_POLICY_H_
