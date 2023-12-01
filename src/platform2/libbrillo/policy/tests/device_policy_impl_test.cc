// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "policy/device_policy_impl.h"

#include "bindings/chrome_device_policy.pb.h"
#include "install_attributes/mock_install_attributes_reader.h"

namespace em = enterprise_management;

using testing::ElementsAre;

namespace policy {

class DevicePolicyImplTest : public testing::Test, public DevicePolicyImpl {
 protected:
  // When |device_mode| is nullptr, the function assumes it's a customer
  // owned device and sets empty install attributes.
  void InitializePolicy(const char* device_mode,
                        const em::ChromeDeviceSettingsProto& proto) {
    device_policy_.set_policy_for_testing(proto);
    if (device_mode) {
      device_policy_.set_install_attributes_for_testing(
          std::make_unique<MockInstallAttributesReader>(
              device_mode, true /* initialized */));
    } else {
      device_policy_.set_install_attributes_for_testing(
          std::make_unique<MockInstallAttributesReader>(
              cryptohome::SerializedInstallAttributes()));
    }
  }

  DevicePolicyImpl device_policy_;
};

// Enterprise managed.
TEST_F(DevicePolicyImplTest, GetOwner_Managed) {
  em::PolicyData policy_data;
  policy_data.set_username("user@example.com");
  policy_data.set_management_mode(em::PolicyData::ENTERPRISE_MANAGED);
  device_policy_.set_policy_data_for_testing(policy_data);

  std::string owner("something");
  EXPECT_TRUE(device_policy_.GetOwner(&owner));
  EXPECT_TRUE(owner.empty());
}

// Consumer owned.
TEST_F(DevicePolicyImplTest, GetOwner_Consumer) {
  em::PolicyData policy_data;
  policy_data.set_username("user@example.com");
  policy_data.set_management_mode(em::PolicyData::LOCAL_OWNER);
  policy_data.set_request_token("codepath-must-ignore-dmtoken");
  device_policy_.set_policy_data_for_testing(policy_data);

  std::string owner;
  EXPECT_TRUE(device_policy_.GetOwner(&owner));
  EXPECT_EQ("user@example.com", owner);
}

// Consumer owned, username is missing.
TEST_F(DevicePolicyImplTest, GetOwner_ConsumerMissingUsername) {
  em::PolicyData policy_data;
  device_policy_.set_policy_data_for_testing(policy_data);

  std::string owner("something");
  EXPECT_FALSE(device_policy_.GetOwner(&owner));
  EXPECT_EQ("something", owner);
}

// Enterprise managed, denoted by management_mode.
TEST_F(DevicePolicyImplTest, IsEnterpriseManaged_ManagementModeManaged) {
  em::PolicyData policy_data;
  policy_data.set_management_mode(em::PolicyData::ENTERPRISE_MANAGED);
  device_policy_.set_policy_data_for_testing(policy_data);

  EXPECT_TRUE(device_policy_.IsEnterpriseManaged());
}

// Enterprise managed, fallback to DM token.
TEST_F(DevicePolicyImplTest, IsEnterpriseManaged_DMTokenManaged) {
  em::PolicyData policy_data;
  policy_data.set_request_token("abc");
  device_policy_.set_policy_data_for_testing(policy_data);

  EXPECT_TRUE(device_policy_.IsEnterpriseManaged());
}

// Consumer owned, denoted by management_mode.
TEST_F(DevicePolicyImplTest, IsEnterpriseManaged_ManagementModeConsumer) {
  em::PolicyData policy_data;
  policy_data.set_management_mode(em::PolicyData::LOCAL_OWNER);
  policy_data.set_request_token("codepath-must-ignore-dmtoken");
  device_policy_.set_policy_data_for_testing(policy_data);

  EXPECT_FALSE(device_policy_.IsEnterpriseManaged());
}

// Consumer owned, fallback to interpreting absence of DM token.
TEST_F(DevicePolicyImplTest, IsEnterpriseManaged_DMTokenConsumer) {
  em::PolicyData policy_data;
  device_policy_.set_policy_data_for_testing(policy_data);

  EXPECT_FALSE(device_policy_.IsEnterpriseManaged());
}

// RollbackAllowedMilestones is not set.
TEST_F(DevicePolicyImplTest, GetRollbackAllowedMilestones_NotSet) {
  device_policy_.set_install_attributes_for_testing(
      std::make_unique<MockInstallAttributesReader>(
          InstallAttributesReader::kDeviceModeEnterprise, true));

  int value = -1;
  ASSERT_TRUE(device_policy_.GetRollbackAllowedMilestones(&value));
  EXPECT_EQ(4, value);
}

// RollbackAllowedMilestones is set to a valid value.
TEST_F(DevicePolicyImplTest, GetRollbackAllowedMilestones_Set) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_rollback_allowed_milestones(3);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  int value = -1;
  ASSERT_TRUE(device_policy_.GetRollbackAllowedMilestones(&value));
  EXPECT_EQ(3, value);
}

// RollbackAllowedMilestones is set to a valid value, but it's not an enterprise
// device.
TEST_F(DevicePolicyImplTest, GetRollbackAllowedMilestones_SetConsumer) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_rollback_allowed_milestones(3);
  InitializePolicy(/*device_mode=*/nullptr, device_policy_proto);

  int value = -1;
  ASSERT_FALSE(device_policy_.GetRollbackAllowedMilestones(&value));
}

// RollbackAllowedMilestones is set to an invalid value.
TEST_F(DevicePolicyImplTest, GetRollbackAllowedMilestones_SetTooLarge) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_rollback_allowed_milestones(10);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  int value = -1;
  ASSERT_TRUE(device_policy_.GetRollbackAllowedMilestones(&value));
  EXPECT_EQ(4, value);
}

// RollbackAllowedMilestones is set to an invalid value.
TEST_F(DevicePolicyImplTest, GetRollbackAllowedMilestones_SetTooSmall) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_rollback_allowed_milestones(-1);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  int value = -1;
  ASSERT_TRUE(device_policy_.GetRollbackAllowedMilestones(&value));
  EXPECT_EQ(0, value);
}

// Update staging schedule has no values
TEST_F(DevicePolicyImplTest, GetDeviceUpdateStagingSchedule_NoValues) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_staging_schedule("[]");
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  std::vector<DayPercentagePair> staging_schedule;
  ASSERT_TRUE(device_policy_.GetDeviceUpdateStagingSchedule(&staging_schedule));
  EXPECT_EQ(0, staging_schedule.size());
}

// Update staging schedule has valid values
TEST_F(DevicePolicyImplTest, GetDeviceUpdateStagingSchedule_Valid) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_staging_schedule(
      "[{\"days\": 4, \"percentage\": 40}, {\"days\": 10, \"percentage\": "
      "100}]");
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  std::vector<DayPercentagePair> staging_schedule;
  ASSERT_TRUE(device_policy_.GetDeviceUpdateStagingSchedule(&staging_schedule));
  EXPECT_THAT(staging_schedule, ElementsAre(DayPercentagePair{4, 40},
                                            DayPercentagePair{10, 100}));
}

// Update staging schedule has values with values set larger than the max
// allowed days/percentage and smaller than the min allowed days/percentage.
TEST_F(DevicePolicyImplTest,
       GetDeviceUpdateStagingSchedule_SetOutsideAllowable) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_staging_schedule(
      "[{\"days\": -1, \"percentage\": -10}, {\"days\": 30, \"percentage\": "
      "110}]");
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  std::vector<DayPercentagePair> staging_schedule;
  ASSERT_TRUE(device_policy_.GetDeviceUpdateStagingSchedule(&staging_schedule));
  EXPECT_THAT(staging_schedule,
              ElementsAre(DayPercentagePair{1, 0}, DayPercentagePair{28, 100}));
}

// Updates should only be disabled for enterprise managed devices.
TEST_F(DevicePolicyImplTest, GetUpdateDisabled_SetConsumer) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_update_disabled(true);
  InitializePolicy(/*device_mode=*/nullptr, device_policy_proto);

  bool value;
  ASSERT_FALSE(device_policy_.GetUpdateDisabled(&value));
}

// Updates should only be pinned on enterprise managed devices.
TEST_F(DevicePolicyImplTest, GetTargetVersionPrefix_SetConsumer) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_target_version_prefix("hello");
  InitializePolicy(/*device_mode=*/nullptr, device_policy_proto);

  std::string value = "";
  ASSERT_FALSE(device_policy_.GetTargetVersionPrefix(&value));
}

// Updates should only be pinned on enterprise managed devices.
TEST_F(DevicePolicyImplTest, GetTargetVersionSelector_SetConsumer) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_target_version_selector("h,ello-v4");
  InitializePolicy(/*device_mode=*/nullptr, device_policy_proto);

  std::string value = "";
  ASSERT_FALSE(device_policy_.GetTargetVersionSelector(&value));
}

TEST_F(DevicePolicyImplTest, GetTargetVersionSelector_Set) {
  constexpr char kExpectedSelectorValue[] = "h,ello-v4";
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_target_version_selector(kExpectedSelectorValue);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  std::string selector_value = "";
  EXPECT_TRUE(device_policy_.GetTargetVersionSelector(&selector_value));
  EXPECT_EQ(selector_value, kExpectedSelectorValue);
}

// The allowed connection types should only be changed in enterprise devices.
TEST_F(DevicePolicyImplTest, GetAllowedConnectionTypesForUpdate_SetConsumer) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->add_allowed_connection_types(
      em::AutoUpdateSettingsProto::CONNECTION_TYPE_ETHERNET);
  InitializePolicy(/*device_mode=*/nullptr, device_policy_proto);

  std::set<std::string> value;
  ASSERT_FALSE(device_policy_.GetAllowedConnectionTypesForUpdate(&value));
}

// Update time restrictions should only be used in enterprise devices.
TEST_F(DevicePolicyImplTest, GetDisallowedTimeIntervals_SetConsumer) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_disallowed_time_intervals(
      "[{\"start\": {\"day_of_week\": \"Monday\", \"hours\": 10, \"minutes\": "
      "0}, \"end\": {\"day_of_week\": \"Monday\", \"hours\": 10, \"minutes\": "
      "0}}]");
  InitializePolicy(/*device_mode=*/nullptr, device_policy_proto);

  std::vector<WeeklyTimeInterval> value;
  ASSERT_FALSE(device_policy_.GetDisallowedTimeIntervals(&value));
}

// |DeviceQuickFixBuildToken| is set when device is enterprise enrolled.
TEST_F(DevicePolicyImplTest, GetDeviceQuickFixBuildToken_Set) {
  const char kToken[] = "some_token";

  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_device_quick_fix_build_token(kToken);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);
  std::string value;
  EXPECT_TRUE(device_policy_.GetDeviceQuickFixBuildToken(&value));
  EXPECT_EQ(value, kToken);
}

// If the device is not enterprise-enrolled, |GetDeviceQuickFixBuildToken|
// does not provide a token even if it is present in local device settings.
TEST_F(DevicePolicyImplTest, GetDeviceQuickFixBuildToken_NotSet) {
  const char kToken[] = "some_token";

  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_device_quick_fix_build_token(kToken);
  InitializePolicy(/*device_mode=*/nullptr, device_policy_proto);
  std::string value;
  EXPECT_FALSE(device_policy_.GetDeviceQuickFixBuildToken(&value));
  EXPECT_TRUE(value.empty());
}

// Should only write a value and return true if the ID is present.
TEST_F(DevicePolicyImplTest, GetDeviceDirectoryApiId_Set) {
  constexpr char kDummyDeviceId[] = "aa-bb-cc-dd";

  em::PolicyData policy_data;
  policy_data.set_directory_api_id(kDummyDeviceId);

  device_policy_.set_policy_data_for_testing(policy_data);

  std::string id;
  EXPECT_TRUE(device_policy_.GetDeviceDirectoryApiId(&id));
  EXPECT_EQ(kDummyDeviceId, id);
}

TEST_F(DevicePolicyImplTest, GetDeviceDirectoryApiId_NotSet) {
  em::PolicyData policy_data;
  device_policy_.set_policy_data_for_testing(policy_data);

  std::string id;
  EXPECT_FALSE(device_policy_.GetDeviceDirectoryApiId(&id));
  EXPECT_TRUE(id.empty());
}

// Should only write a value and return true as the ID should be present.
TEST_F(DevicePolicyImplTest, GetCustomerId_Set) {
  constexpr char kDummyCustomerId[] = "customerId";

  em::PolicyData policy_data;
  policy_data.set_obfuscated_customer_id(kDummyCustomerId);

  device_policy_.set_policy_data_for_testing(policy_data);

  std::string id;
  EXPECT_TRUE(device_policy_.GetCustomerId(&id));
  EXPECT_EQ(kDummyCustomerId, id);
}

TEST_F(DevicePolicyImplTest, GetCustomerId_NotSet) {
  em::PolicyData policy_data;
  device_policy_.set_policy_data_for_testing(policy_data);

  std::string id;
  EXPECT_FALSE(device_policy_.GetCustomerId(&id));
  EXPECT_TRUE(id.empty());
}

TEST_F(DevicePolicyImplTest, GetReleaseLtsTagSet) {
  const char kLtsTag[] = "abc";

  em::ChromeDeviceSettingsProto device_policy_proto;
  auto* release_channel = device_policy_proto.mutable_release_channel();
  release_channel->set_release_lts_tag(kLtsTag);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  std::string lts_tag;
  EXPECT_TRUE(device_policy_.GetReleaseLtsTag(&lts_tag));
  EXPECT_EQ(lts_tag, kLtsTag);
}

TEST_F(DevicePolicyImplTest, GetReleaseLtsTagNotSet) {
  const char kChannel[] = "stable-channel";

  em::ChromeDeviceSettingsProto device_policy_proto;
  std::string lts_tag;

  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);
  EXPECT_FALSE(device_policy_.GetReleaseLtsTag(&lts_tag));
  EXPECT_TRUE(lts_tag.empty());

  // Add release_channel without lts_tag to the proto by setting an unrelated
  // field.
  auto* release_channel = device_policy_proto.mutable_release_channel();
  release_channel->set_release_channel(kChannel);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  EXPECT_FALSE(device_policy_.GetReleaseLtsTag(&lts_tag));
  EXPECT_TRUE(lts_tag.empty());
}

TEST_F(DevicePolicyImplTest, GetChannelDowngradeBehaviorSet) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::AutoUpdateSettingsProto* auto_update_settings =
      device_policy_proto.mutable_auto_update_settings();
  auto_update_settings->set_channel_downgrade_behavior(
      em::AutoUpdateSettingsProto::ChannelDowngradeBehavior
        ::AutoUpdateSettingsProto_ChannelDowngradeBehavior_ROLLBACK);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  int value = -1;
  EXPECT_TRUE(device_policy_.GetChannelDowngradeBehavior(&value));
  EXPECT_EQ(static_cast<int>(
      em::AutoUpdateSettingsProto::ChannelDowngradeBehavior
        ::AutoUpdateSettingsProto_ChannelDowngradeBehavior_ROLLBACK), value);
}

TEST_F(DevicePolicyImplTest, GetChannelDowngradeBehaviorNotSet) {
  em::PolicyData policy_data;
  device_policy_.set_policy_data_for_testing(policy_data);

  int value = -1;
  EXPECT_FALSE(device_policy_.GetChannelDowngradeBehavior(&value));
}

// Device minimum required version should only be used in enterprise devices.
TEST_F(DevicePolicyImplTest, GetHighestDeviceMinimumVersion_SetConsumer) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  device_policy_proto.mutable_device_minimum_version()->set_value(
      "{\"requirements\" : [{\"chromeos_version\" : \"12215\", "
      "\"warning_period\" : 7, \"aue_warning_period\" : 14},  "
      "{\"chromeos_version\" : \"13315.60.12\", \"warning_period\" : 5, "
      "\"aue_warning_period\" : 13}], \"unmanaged_user_restricted\" : true}");
  InitializePolicy(/*device_mode=*/nullptr, device_policy_proto);

  base::Version version;
  ASSERT_FALSE(device_policy_.GetHighestDeviceMinimumVersion(&version));
}

// Should only write a value and return true as the
// |device_market_segment| should be present.
TEST_F(DevicePolicyImplTest, GetDeviceMarketSegment_EducationDevice) {
  em::PolicyData policy_data;
  policy_data.set_market_segment(em::PolicyData::ENROLLED_EDUCATION);
  device_policy_.set_policy_data_for_testing(policy_data);

  DeviceMarketSegment segment;
  EXPECT_TRUE(device_policy_.GetDeviceMarketSegment(&segment));
  EXPECT_EQ(segment, DeviceMarketSegment::kEducation);
}

TEST_F(DevicePolicyImplTest, GetDeviceMarketSegment_UnspecifiedDevice) {
  em::PolicyData policy_data;
  policy_data.set_market_segment(em::PolicyData::MARKET_SEGMENT_UNSPECIFIED);
  device_policy_.set_policy_data_for_testing(policy_data);

  DeviceMarketSegment segment;
  EXPECT_TRUE(device_policy_.GetDeviceMarketSegment(&segment));
  EXPECT_EQ(segment, DeviceMarketSegment::kUnknown);
}

TEST_F(DevicePolicyImplTest, GetDeviceMarketSegment_NotSet) {
  em::PolicyData policy_data;
  device_policy_.set_policy_data_for_testing(policy_data);

  DeviceMarketSegment segment;
  EXPECT_FALSE(device_policy_.GetDeviceMarketSegment(&segment));
}

TEST_F(DevicePolicyImplTest,
       GetDeviceKeylockerForStorageEncryptionEnabled_SetEnabled) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::DeviceKeylockerForStorageEncryptionEnabledProto* kl_proto =
      device_policy_proto.mutable_keylocker_for_storage_encryption_enabled();
  kl_proto->set_enabled(true);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  bool kl_enabled = false;
  EXPECT_TRUE(device_policy_.GetDeviceKeylockerForStorageEncryptionEnabled(
      &kl_enabled));
  EXPECT_TRUE(kl_enabled);
}

TEST_F(DevicePolicyImplTest,
       GetDeviceKeylockerForStorageEncryptionEnabled_NotSet) {
  em::PolicyData policy_data;
  device_policy_.set_policy_data_for_testing(policy_data);
  bool kl_enabled = false;
  EXPECT_FALSE(device_policy_.GetDeviceKeylockerForStorageEncryptionEnabled(
      &kl_enabled));
}

// Policy should only apply to enterprise devices.
TEST_F(DevicePolicyImplTest, GetRunAutomaticCleanupOnLogin_SetConsumer) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::BooleanPolicyProto* run_settings =
      device_policy_proto.mutable_device_run_automatic_cleanup_on_login();
  run_settings->set_value(true);
  InitializePolicy(/*device_mode=*/nullptr, device_policy_proto);

  ASSERT_THAT(device_policy_.GetRunAutomaticCleanupOnLogin(),
              testing::Eq(std::nullopt));
}

TEST_F(DevicePolicyImplTest, GetRunAutomaticCleanupOnLogin_Set) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::BooleanPolicyProto* run_settings =
      device_policy_proto.mutable_device_run_automatic_cleanup_on_login();
  run_settings->set_value(true);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  ASSERT_THAT(device_policy_.GetRunAutomaticCleanupOnLogin(),
              testing::Eq(std::optional(true)));
}

TEST_F(DevicePolicyImplTest, GetReportDeviceSecurityStatus_NotSet) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  ASSERT_THAT(device_policy_.GetReportDeviceSecurityStatus(),
              testing::Eq(std::nullopt));
}

TEST_F(DevicePolicyImplTest, GetReportDeviceSecurityStatus_Set) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::DeviceReportingProto* device_reporting =
      device_policy_proto.mutable_device_reporting();
  device_reporting->set_report_security_status(true);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  ASSERT_THAT(device_policy_.GetReportDeviceSecurityStatus(),
              testing::Eq(std::optional(true)));
}

TEST_F(DevicePolicyImplTest, GetDeviceReportXDREvents_NotSet) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  ASSERT_THAT(device_policy_.GetDeviceReportXDREvents(),
              testing::Eq(std::nullopt));
}

TEST_F(DevicePolicyImplTest, GetDeviceReportXDREvents_Set) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::DeviceReportXDREventsProto* xdr_reporting =
      device_policy_proto.mutable_device_report_xdr_events();
  xdr_reporting->set_enabled(true);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  ASSERT_THAT(device_policy_.GetDeviceReportXDREvents(),
              testing::Eq(std::optional(true)));
}

TEST_F(DevicePolicyImplTest, GetEphemeralSettings_NotSet) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  DevicePolicy::EphemeralSettings ephemeral_settings;
  EXPECT_FALSE(device_policy_.GetEphemeralSettings(&ephemeral_settings));
  EXPECT_FALSE(ephemeral_settings.global_ephemeral_users_enabled);
  EXPECT_TRUE(ephemeral_settings.specific_ephemeral_users.empty());
  EXPECT_TRUE(ephemeral_settings.specific_nonephemeral_users.empty());
}

TEST_F(DevicePolicyImplTest,
       GetEphemeralSettings_Set_EphemeralUsersEnabled_True) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  device_policy_proto.mutable_ephemeral_users_enabled()
      ->set_ephemeral_users_enabled(true);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  DevicePolicy::EphemeralSettings ephemeral_settings;
  EXPECT_TRUE(device_policy_.GetEphemeralSettings(&ephemeral_settings));
  EXPECT_TRUE(ephemeral_settings.global_ephemeral_users_enabled);
  EXPECT_TRUE(ephemeral_settings.specific_ephemeral_users.empty());
  EXPECT_TRUE(ephemeral_settings.specific_nonephemeral_users.empty());
}

TEST_F(DevicePolicyImplTest,
       GetEphemeralSettings_Set_EphemeralUsersEnabled_False) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  device_policy_proto.mutable_ephemeral_users_enabled()
      ->set_ephemeral_users_enabled(false);
  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  DevicePolicy::EphemeralSettings ephemeral_settings;
  EXPECT_TRUE(device_policy_.GetEphemeralSettings(&ephemeral_settings));
  EXPECT_FALSE(ephemeral_settings.global_ephemeral_users_enabled);
  EXPECT_TRUE(ephemeral_settings.specific_ephemeral_users.empty());
  EXPECT_TRUE(ephemeral_settings.specific_nonephemeral_users.empty());
}

TEST_F(DevicePolicyImplTest, GetEphemeralSettings_Set_Non_Ephemeral_User) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::DeviceLocalAccountInfoProto* account =
      device_policy_proto.mutable_device_local_accounts()->add_account();
  account->set_account_id("account");
  account->set_ephemeral_mode(
      em::DeviceLocalAccountInfoProto::EPHEMERAL_MODE_DISABLE);

  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  DevicePolicy::EphemeralSettings ephemeral_settings;
  EXPECT_TRUE(device_policy_.GetEphemeralSettings(&ephemeral_settings));
  EXPECT_FALSE(ephemeral_settings.global_ephemeral_users_enabled);
  EXPECT_TRUE(ephemeral_settings.specific_ephemeral_users.empty());
  EXPECT_EQ(1, ephemeral_settings.specific_nonephemeral_users.size());
  EXPECT_EQ("6163636f756e74@public-accounts.device-local.localhost",
            ephemeral_settings.specific_nonephemeral_users[0]);
}

TEST_F(DevicePolicyImplTest, GetEphemeralSettings_Set_Ephemeral_User) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  em::DeviceLocalAccountInfoProto* account =
      device_policy_proto.mutable_device_local_accounts()->add_account();
  account->set_account_id("account");
  account->set_ephemeral_mode(
      em::DeviceLocalAccountInfoProto::EPHEMERAL_MODE_ENABLE);

  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  DevicePolicy::EphemeralSettings ephemeral_settings;
  EXPECT_TRUE(device_policy_.GetEphemeralSettings(&ephemeral_settings));
  EXPECT_FALSE(ephemeral_settings.global_ephemeral_users_enabled);
  EXPECT_EQ(1, ephemeral_settings.specific_ephemeral_users.size());
  EXPECT_EQ("6163636f756e74@public-accounts.device-local.localhost",
            ephemeral_settings.specific_ephemeral_users[0]);
  EXPECT_TRUE(ephemeral_settings.specific_nonephemeral_users.empty());
}

TEST_F(DevicePolicyImplTest, GetEphemeralSettings_Set_EphemeralMode_Unset) {
  em::ChromeDeviceSettingsProto device_policy_proto;
  device_policy_proto.mutable_ephemeral_users_enabled()
      ->set_ephemeral_users_enabled(true);
  em::DeviceLocalAccountsProto* device_local_accounts =
      device_policy_proto.mutable_device_local_accounts();

  em::DeviceLocalAccountInfoProto* account1 =
      device_local_accounts->add_account();
  account1->set_account_id("account1");
  account1->set_ephemeral_mode(
      em::DeviceLocalAccountInfoProto::EPHEMERAL_MODE_UNSET);

  em::DeviceLocalAccountInfoProto* account2 =
      device_local_accounts->add_account();
  account2->set_account_id("account2");
  account2->set_ephemeral_mode(em::DeviceLocalAccountInfoProto::
                                   EPHEMERAL_MODE_FOLLOW_DEVICE_WIDE_POLICY);

  InitializePolicy(InstallAttributesReader::kDeviceModeEnterprise,
                   device_policy_proto);

  DevicePolicy::EphemeralSettings ephemeral_settings;
  EXPECT_TRUE(device_policy_.GetEphemeralSettings(&ephemeral_settings));
  EXPECT_TRUE(ephemeral_settings.global_ephemeral_users_enabled);
  EXPECT_TRUE(ephemeral_settings.specific_ephemeral_users.empty());
  EXPECT_TRUE(ephemeral_settings.specific_nonephemeral_users.empty());
}

}  // namespace policy
