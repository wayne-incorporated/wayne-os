// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_POLICY_DEVICE_POLICY_H_
#define LIBBRILLO_POLICY_DEVICE_POLICY_H_

#include <stdint.h>

#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <base/time/time.h>
#include <base/version.h>

#pragma GCC visibility push(default)

namespace policy {

// This class holds device settings that are to be enforced across all users.
// It is also responsible for loading the policy blob from disk and verifying
// the signature against the owner's key.
//
// This class defines the interface for querying device policy on ChromeOS.
// The implementation is hidden in DevicePolicyImpl to prevent protobuf
// definition from leaking into the libraries using this interface.
// TODO(b:184745765) Refactor the Getters return bool type and pointer style
class DevicePolicy {
 public:
  // Identifiers of a USB device or device family.
  struct UsbDeviceId {
    // USB Vendor Identifier (aka idVendor).
    uint16_t vendor_id;

    // USB Product Identifier (aka idProduct).
    uint16_t product_id;
  };

  // Time interval represented by two |day_of_week| and |time| pairs. The start
  // of the interval is inclusive and the end is exclusive. The time represented
  // by those pairs will be interpreted to be in the local timezone. Because of
  // this, there exists the possibility of intervals being repeated or skipped
  // in a day with daylight savings transitions, this is expected behavior.
  struct WeeklyTimeInterval {
    // Value is from 1 to 7 (1 = Monday, 2 = Tuesday, etc.). All values outside
    // this range are invalid and will be discarded.
    int start_day_of_week;
    // Time since the start of the day. This value will be interpreted to be in
    // the system's current timezone when used for range checking.
    base::TimeDelta start_time;
    int end_day_of_week;
    base::TimeDelta end_time;
  };

  // Identifies a <day, percentage> pair in a staging schedule.
  struct DayPercentagePair {
    bool operator==(const DayPercentagePair& other) const {
      return days == other.days && percentage == other.percentage;
    }
    int days;
    int percentage;
  };

  // Device Market Segment enum which is translated from MarketSegment in
  // components/policy/proto/device_management_backend.proto.
  enum class DeviceMarketSegment {
    kUnknown = 0,
    kEducation,
    kEnterprise,
  };

  // Ephemeral Settings which are generated from DeviceLocalAccountInfoProto
  // ephemeral_mode value and EphemeralUsersEnabledProto.
  struct EphemeralSettings {
    bool global_ephemeral_users_enabled = false;
    std::vector<std::string> specific_ephemeral_users;
    std::vector<std::string> specific_nonephemeral_users;
  };

  DevicePolicy();
  DevicePolicy(const DevicePolicy&) = delete;
  DevicePolicy& operator=(const DevicePolicy&) = delete;

  virtual ~DevicePolicy();

  // Load device policy off of disk into |policy_|.
  // Returns true unless there is a policy on disk and loading it fails.
  // If |delete_invalid_files| is set to true, it deletes the files for
  // which the policy loading failed.
  virtual bool LoadPolicy(bool delete_invalid_files) = 0;

  // Returns true if OOBE has been completed and if the device has been enrolled
  // as an enterprise or enterpriseAD device.
  virtual bool IsEnterpriseEnrolled() const = 0;

  // Writes the value of the DevicePolicyRefreshRate policy in |rate|. Returns
  // true on success.
  virtual bool GetPolicyRefreshRate(int* rate) const = 0;

  // Writes the value of the GuestModeEnabled policy in |guest_mode_enabled|.
  // Returns true on success.
  virtual bool GetGuestModeEnabled(bool* guest_mode_enabled) const = 0;

  // Writes the value of the CameraEnabled policy in |camera_enabled|. Returns
  // true on success.
  virtual bool GetCameraEnabled(bool* camera_enabled) const = 0;

  // Writes the value of the ShowUserNamesOnSignIn policy in |show_user_names|.
  // Returns true on success.
  virtual bool GetShowUserNames(bool* show_user_names) const = 0;

  // Writes the value of the DataRoamingEnabled policy in |data_roaming_enabled|
  // Returns true on success.
  virtual bool GetDataRoamingEnabled(bool* data_roaming_enabled) const = 0;

  // Writes the value of the AllowNewUsers policy in |allow_new_users|. Returns
  // true on success.
  virtual bool GetAllowNewUsers(bool* allow_new_users) const = 0;

  // Writes the value of MetricEnabled policy in |metrics_enabled|. Returns true
  // on success.
  virtual bool GetMetricsEnabled(bool* metrics_enabled) const = 0;

  // Writes the value of ReportVersionInfo policy in |report_version_info|.
  // Returns true on success.
  virtual bool GetReportVersionInfo(bool* report_version_info) const = 0;

  // Writes the value of ReportActivityTimes policy in |report_activity_times|.
  // Returns true on success.
  virtual bool GetReportActivityTimes(bool* report_activity_times) const = 0;

  // Writes the value of ReportBootMode policy in |report_boot_mode|. Returns
  // true on success.
  virtual bool GetReportBootMode(bool* report_boot_mode) const = 0;

  // Writes the value of the EphemeralUsersEnabled policy and the values from
  // DeviceLocalAccountInfoProto EphemeralMode to |ephemeral_settings|.
  // Returns true if either of the policies are present.
  virtual bool GetEphemeralSettings(
      EphemeralSettings* ephemeral_settings) const = 0;

  // Writes the value of the release channel policy in |release_channel|.
  // Returns true on success.
  virtual bool GetReleaseChannel(std::string* release_channel) const = 0;

  // Writes the value of the release_channel_delegated policy in
  // |release_channel_delegated|. Returns true on success.
  virtual bool GetReleaseChannelDelegated(
      bool* release_channel_delegated) const = 0;

  // Writes the value of the release LTS tag policy in |lts_tag|.
  // Returns true on success.
  virtual bool GetReleaseLtsTag(std::string* lts_tag) const = 0;

  // Writes the value of the update_disabled policy in |update_disabled|.
  // Returns true on success.
  virtual bool GetUpdateDisabled(bool* update_disabled) const = 0;

  // Writes the value of the target_version_prefix policy in
  // |target_version_prefix|. Returns true on success.
  virtual bool GetTargetVersionPrefix(
      std::string* target_version_prefix) const = 0;

  // Writes the value of the target_version_selector policy in
  // |target_version_selector|. Returns true on success.
  virtual bool GetTargetVersionSelector(
      std::string* target_version_selector) const = 0;

  // Writes the value of the rollback_to_target_version policy in
  // |rollback_to_target_version|. |rollback_to_target_version| will be one of
  // the values in AutoUpdateSettingsProto's RollbackToTargetVersion enum.
  // Returns true on success.
  virtual bool GetRollbackToTargetVersion(
      int* rollback_to_target_version) const = 0;

  // Writes the value of the rollback_allowed_milestones policy in
  // |rollback_allowed_milestones|. Returns true on success.
  virtual bool GetRollbackAllowedMilestones(
      int* rollback_allowed_milestones) const = 0;

  // Writes the value of the scatter_factor_in_seconds policy in
  // |scatter_factor_in_seconds|. Returns true on success.
  virtual bool GetScatterFactorInSeconds(
      int64_t* scatter_factor_in_seconds) const = 0;

  // Writes the connection types on which updates are allowed to
  // |connection_types|. The identifiers returned are intended to be consistent
  // with what the connection manager users: ethernet, wifi, wimax, bluetooth,
  // cellular.
  virtual bool GetAllowedConnectionTypesForUpdate(
      std::set<std::string>* connection_types) const = 0;

  // Writes the value of the OpenNetworkConfiguration policy in
  // |open_network_configuration|. Returns true on success.
  virtual bool GetOpenNetworkConfiguration(
      std::string* open_network_configuration) const = 0;

  // Writes the name of the device owner in |owner|. For enterprise enrolled
  // devices, this will be an empty string.
  // Returns true on success.
  virtual bool GetOwner(std::string* owner) const = 0;

  // Write the value of http_downloads_enabled policy in
  // |http_downloads_enabled|. Returns true on success.
  virtual bool GetHttpDownloadsEnabled(bool* http_downloads_enabled) const = 0;

  // Writes the value of au_p2p_enabled policy in
  // |au_p2p_enabled|. Returns true on success.
  virtual bool GetAuP2PEnabled(bool* au_p2p_enabled) const = 0;

  // Writes the value of allow_kiosk_app_control_chrome_version policy in
  // |allow_kiosk_app_control_chrome_version|. Returns true on success.
  virtual bool GetAllowKioskAppControlChromeVersion(
      bool* allow_kiosk_app_control_chrome_version) const = 0;

  // Writes the value of the UsbDetachableWhitelist policy in |usb_whitelist|.
  // Returns true on success.
  virtual bool GetUsbDetachableWhitelist(
      std::vector<UsbDeviceId>* usb_whitelist) const = 0;

  // Writes the value of the kiosk app id into |app_id_out|.
  // Only succeeds if the device is in auto-launched kiosk mode.
  virtual bool GetAutoLaunchedKioskAppId(std::string* app_id_out) const = 0;

  // Returns true if the policy data indicates that the device is enterprise
  // managed. Note that this potentially could be faked by an exploit, therefore
  // InstallAttributesReader must be used when tamper-proof evidence of the
  // management state is required.
  virtual bool IsEnterpriseManaged() const = 0;

  // Writes the value of the DeviceSecondFactorAuthentication policy in
  // |mode_out|. |mode_out| is one of the values from
  // DeviceSecondFactorAuthenticationProto's U2fMode enum (e.g. DISABLED,
  // U2F or U2F_EXTENDED). Returns true on success.
  virtual bool GetSecondFactorAuthenticationMode(int* mode_out) const = 0;

  // Returns the value of the DeviceRunAutomaticCleanupOnLogin policy. On
  // error or if the policy is not set, returns an empty value.
  virtual std::optional<bool> GetRunAutomaticCleanupOnLogin() const = 0;

  // Writes the valid time intervals to |intervals_out|. These
  // intervals are taken from the disallowed time intervals field in the
  // AutoUpdateSettingsProto. Returns true if the intervals in the proto are
  // valid.
  virtual bool GetDisallowedTimeIntervals(
      std::vector<WeeklyTimeInterval>* intervals_out) const = 0;

  // Writes the value of the DeviceUpdateStagingSchedule policy to
  // |staging_schedule_out|. Returns true on success.
  // The schedule is a list of <days, percentage> pairs. The percentages are
  // expected to be mononically increasing in the range of [1, 100]. Similarly,
  // days are expected to be monotonically increasing in the range [1, 28]. Each
  // pair describes the |percentage| of the fleet that is expected to receive an
  // update after |days| days after an update was discovered. e.g. [<4, 30>, <8,
  // 100>] means that 30% of devices should be updated in the first 4 days, and
  // then 100% should be updated after 8 days.
  virtual bool GetDeviceUpdateStagingSchedule(
      std::vector<DayPercentagePair>* staging_schedule_out) const = 0;

  // Writes the value of the DeviceQuickFixBuildToken to
  // |device_quick_fix_build_token|.
  // Returns true if it has been written, or false if the policy was not set.
  virtual bool GetDeviceQuickFixBuildToken(
      std::string* device_quick_fix_build_token) const = 0;

  // Writes the value of the Directory API ID to |directory_api_id_out|.
  // Returns true on success, false if the ID is not available (eg if the device
  // is not enrolled).
  virtual bool GetDeviceDirectoryApiId(
      std::string* directory_api_id_out) const = 0;

  // Writes the value of the Customer ID to |customer_id_out|.
  // Returns true on success, false if the ID is not available (eg if the device
  // is not enrolled).
  virtual bool GetCustomerId(std::string* customer_id_out) const = 0;

  // Writes the value of ChannelDowngradeBehavior policy into
  // |channel_downgrade_behavior_out|. |channel_downgrade_behavior_out| will be
  // one of the values in AutoUpdateSettingsProto's ChannelDowngradeBehavior
  // enum. Returns true on success.
  virtual bool GetChannelDowngradeBehavior(
      int* channel_downgrade_behavior_out) const = 0;

  // Writes the value of Chrome OS minimum required version. This value
  // is taken from the list of versions of device_minimum_version field of the
  // ChromeDeviceSettingsProto. The value is the highest version listed in
  // policy. Returns true if the policy is a valid JSON dictionary containing at
  // least one valid version entry. Returns false if the policy is not set or no
  // version can be parsed from it.
  virtual bool GetHighestDeviceMinimumVersion(
      base::Version* versions_out) const = 0;

  // Write the value of the DeviceMarketSegment policy in
  // |device_market_segment|. Returns true on success. If the proto value is
  // not set, then return false.
  // Translated value from MarketSegment in device_management_backend.proto
  virtual bool GetDeviceMarketSegment(
      DeviceMarketSegment* device_market_segment) const = 0;

  // Write the value of the DeviceKeylockerForStorageEncryptionEnabled policy in
  // |keylocker_enabled|. Returns true on success.
  virtual bool GetDeviceKeylockerForStorageEncryptionEnabled(
      bool* keylocker_enabled) const = 0;

  // Writes the value of DevicePacketCaptureAllowed policy in |allowed|. Returns
  // true if the policy was set and a value was retrieved for it, or false if
  // the policy was not set. |allowed| is modified only when the function
  // returns true.
  virtual bool GetDeviceDebugPacketCaptureAllowed(bool* allowed) const = 0;

  // Returns the value of the ReportDeviceSecurityStatus policy. On
  // error or if the policy is not set, returns an empty value.
  virtual std::optional<bool> GetReportDeviceSecurityStatus() const = 0;

  // Returns the value of the DeviceReportXDREvents policy. On
  // error or if the policy is not set, return an empty value.
  virtual std::optional<bool> GetDeviceReportXDREvents() const = 0;

 private:
  // Verifies that the policy signature is correct.
  virtual bool VerifyPolicySignature() = 0;
};
}  // namespace policy

#pragma GCC visibility pop

#endif  // LIBBRILLO_POLICY_DEVICE_POLICY_H_
