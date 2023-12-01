// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "policy/libpolicy.h"

#include <memory>
#include <utility>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <base/files/file_path.h>
#include <base/logging.h>
#include <gtest/gtest.h>

#include "bindings/chrome_device_policy.pb.h"
#include "install_attributes/mock_install_attributes_reader.h"
#include "policy/device_policy_impl.h"

namespace policy {

static const char kPolicyFileAllSet[] =
    "policy/tests/devicesettings/policy_all.bin";
static const char kPolicyFileNoneSet[] =
    "policy/tests/devicesettings/policy_none.bin";
static const char kKeyFile[] = "policy/tests/devicesettings/owner.key";
static const char kNonExistingFile[] = "file-does-not-exist";

// Creates the DevicePolicyImpl with given parameters for test.
std::unique_ptr<DevicePolicyImpl> CreateDevicePolicyImpl(
    std::unique_ptr<InstallAttributesReader> install_attributes_reader,
    const base::FilePath& policy_path,
    const base::FilePath& keyfile_path,
    bool verify_files) {
  std::unique_ptr<DevicePolicyImpl> device_policy(new DevicePolicyImpl());
  device_policy->set_install_attributes_for_testing(
      std::move(install_attributes_reader));
  device_policy->set_policy_path_for_testing(policy_path);
  device_policy->set_key_file_path_for_testing(keyfile_path);
  device_policy->set_verify_root_ownership_for_testing(verify_files);

  return device_policy;
}

// Test that a policy file can be verified and parsed correctly. The file
// contains all possible fields, so reading should succeed for all.
TEST(PolicyTest, DevicePolicyAllSetTest) {
  base::FilePath policy_file(kPolicyFileAllSet);
  base::FilePath key_file(kKeyFile);
  PolicyProvider provider;
  provider.SetDevicePolicyForTesting(CreateDevicePolicyImpl(
      std::make_unique<MockInstallAttributesReader>(
          InstallAttributesReader::kDeviceModeEnterprise, true),
      policy_file, key_file, false));
  provider.Reload();

  // Ensure we successfully loaded the device policy file.
  ASSERT_TRUE(provider.device_policy_is_loaded());

  const DevicePolicy& policy = provider.GetDevicePolicy();

  // Check that we can read out all fields of the sample protobuf.
  int int_value = -1;
  ASSERT_TRUE(policy.GetPolicyRefreshRate(&int_value));
  EXPECT_EQ(100, int_value);

  bool bool_value = true;
  ASSERT_TRUE(policy.GetGuestModeEnabled(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetCameraEnabled(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetShowUserNames(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetDataRoamingEnabled(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetAllowNewUsers(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetMetricsEnabled(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetReportVersionInfo(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetReportActivityTimes(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetReportBootMode(&bool_value));
  EXPECT_FALSE(bool_value);

  DevicePolicy::EphemeralSettings ephemeral_settings;
  ASSERT_TRUE(policy.GetEphemeralSettings(&ephemeral_settings));
  EXPECT_FALSE(ephemeral_settings.global_ephemeral_users_enabled);

  std::string string_value;
  ASSERT_TRUE(policy.GetReleaseChannel(&string_value));
  EXPECT_EQ("stable-channel", string_value);

  bool_value = false;
  ASSERT_TRUE(policy.GetReleaseChannelDelegated(&bool_value));
  EXPECT_TRUE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetUpdateDisabled(&bool_value));
  EXPECT_FALSE(bool_value);

  int64_t int64_value = -1LL;
  ASSERT_TRUE(policy.GetScatterFactorInSeconds(&int64_value));
  EXPECT_EQ(17LL, int64_value);

  ASSERT_TRUE(policy.GetTargetVersionPrefix(&string_value));
  EXPECT_EQ("42.0.", string_value);

  ASSERT_TRUE(policy.GetTargetVersionSelector(&string_value));
  EXPECT_EQ("0,1626155736-", string_value);

  int_value = -1;
  if (USE_ENTERPRISE_ROLLBACK_REVEN) {
    ASSERT_FALSE(policy.GetRollbackToTargetVersion(&int_value));
  } else {
    ASSERT_TRUE(policy.GetRollbackToTargetVersion(&int_value));
    EXPECT_EQ(
        enterprise_management::AutoUpdateSettingsProto::ROLLBACK_AND_POWERWASH,
        int_value);
  }

  int_value = -1;
  ASSERT_TRUE(policy.GetRollbackAllowedMilestones(&int_value));
  EXPECT_EQ(3, int_value);

  std::set<std::string> types;
  ASSERT_TRUE(policy.GetAllowedConnectionTypesForUpdate(&types));
  EXPECT_TRUE(types.end() != types.find("ethernet"));
  EXPECT_TRUE(types.end() != types.find("wifi"));
  EXPECT_EQ(2, types.size());

  ASSERT_TRUE(policy.GetOpenNetworkConfiguration(&string_value));
  EXPECT_EQ("{}", string_value);

  ASSERT_TRUE(policy.GetOwner(&string_value));
  EXPECT_EQ("", string_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetHttpDownloadsEnabled(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetAuP2PEnabled(&bool_value));
  EXPECT_FALSE(bool_value);

  bool_value = true;
  ASSERT_TRUE(policy.GetAllowKioskAppControlChromeVersion(&bool_value));
  EXPECT_FALSE(bool_value);

  // Note: policy data contains both the old usb_detachable_whitelist and the
  // new usb_detachable_allowlist.
  //
  // Test that only the allowlist is considered.
  std::vector<DevicePolicy::UsbDeviceId> list_device;
  ASSERT_TRUE(policy.GetUsbDetachableWhitelist(&list_device));
  ASSERT_EQ(2, list_device.size());
  // In the new usb_detachable_allowlist.
  EXPECT_EQ(0x413c, list_device[0].vendor_id);
  EXPECT_EQ(0x2105, list_device[0].product_id);
  EXPECT_EQ(0x0403, list_device[1].vendor_id);
  EXPECT_EQ(0x6001, list_device[1].product_id);

  ASSERT_TRUE(policy.GetAutoLaunchedKioskAppId(&string_value));
  EXPECT_EQ("my_kiosk_app", string_value);

  int_value = -1;
  ASSERT_TRUE(policy.GetSecondFactorAuthenticationMode(&int_value));
  EXPECT_EQ(2, int_value);

  std::vector<DevicePolicy::WeeklyTimeInterval> intervals;
  ASSERT_TRUE(policy.GetDisallowedTimeIntervals(&intervals));
  ASSERT_EQ(2, intervals.size());
  EXPECT_EQ(4, intervals[0].start_day_of_week);
  EXPECT_EQ(base::Minutes(30) + base::Hours(12), intervals[0].start_time);
  EXPECT_EQ(6, intervals[0].end_day_of_week);
  EXPECT_EQ(base::Minutes(15) + base::Hours(3), intervals[0].end_time);
  EXPECT_EQ(1, intervals[1].start_day_of_week);
  EXPECT_EQ(base::Minutes(10) + base::Hours(20), intervals[1].start_time);
  EXPECT_EQ(3, intervals[1].end_day_of_week);
  EXPECT_EQ(base::Minutes(20), intervals[1].end_time);

  base::Version device_minimum_version;
  const base::Version expected_minimum_version("13315.60.12");
  ASSERT_TRUE(policy.GetHighestDeviceMinimumVersion(&device_minimum_version));
  EXPECT_EQ(expected_minimum_version, device_minimum_version);

  // Reloading the protobuf should succeed.
  EXPECT_TRUE(provider.Reload());
}

// Test the deprecated usb_detachable_whitelist using a copy of the test policy
// data and removing the usb_detachable_allowlist.
TEST(PolicyTest, DevicePolicyWhitelistTest) {
  base::FilePath policy_file(kPolicyFileAllSet);
  base::FilePath key_file(kKeyFile);
  PolicyProvider provider;
  provider.SetDevicePolicyForTesting(CreateDevicePolicyImpl(
      std::make_unique<MockInstallAttributesReader>(
          InstallAttributesReader::kDeviceModeEnterprise, true),
      policy_file, key_file, false));
  provider.Reload();

  // Ensure we successfully loaded the device policy file.
  ASSERT_TRUE(provider.device_policy_is_loaded());

  enterprise_management::ChromeDeviceSettingsProto proto =
      static_cast<const DevicePolicyImpl&>(provider.GetDevicePolicy())
          .get_device_policy();
  proto.clear_usb_detachable_allowlist();
  ASSERT_FALSE(proto.has_usb_detachable_allowlist());
  ASSERT_TRUE(proto.has_usb_detachable_whitelist());

  DevicePolicyImpl device_policy;
  device_policy.set_policy_for_testing(proto);

  std::vector<DevicePolicy::UsbDeviceId> list_device;
  ASSERT_TRUE(device_policy.GetUsbDetachableWhitelist(&list_device));
  ASSERT_EQ(1, list_device.size());
  EXPECT_EQ(0x01d1, list_device[0].vendor_id);
  EXPECT_EQ(0xdead, list_device[0].product_id);
}

// Test that a policy file can be verified and parsed correctly. The file
// contains none of the possible fields, so reading should fail for all.
TEST(PolicyTest, DevicePolicyNoneSetTest) {
  base::FilePath policy_file(kPolicyFileNoneSet);
  base::FilePath key_file(kKeyFile);

  PolicyProvider provider;
  provider.SetDevicePolicyForTesting(CreateDevicePolicyImpl(
      std::make_unique<MockInstallAttributesReader>(
          InstallAttributesReader::kDeviceModeEnterprise, true),
      policy_file, key_file, false));
  provider.Reload();

  // Ensure we successfully loaded the device policy file.
  ASSERT_TRUE(provider.device_policy_is_loaded());

  const DevicePolicy& policy = provider.GetDevicePolicy();

  // Check that we cannot read any fields out of the sample protobuf.
  int int_value;
  int64_t int64_value;
  bool bool_value;
  std::string string_value;
  std::vector<DevicePolicy::UsbDeviceId> list_device;
  std::vector<DevicePolicy::WeeklyTimeInterval> intervals;
  base::Version device_minimum_version;
  DevicePolicy::EphemeralSettings ephemeral_settings;

  EXPECT_FALSE(policy.GetPolicyRefreshRate(&int_value));
  EXPECT_FALSE(policy.GetGuestModeEnabled(&bool_value));
  EXPECT_FALSE(policy.GetCameraEnabled(&bool_value));
  EXPECT_FALSE(policy.GetShowUserNames(&bool_value));
  EXPECT_FALSE(policy.GetDataRoamingEnabled(&bool_value));
  EXPECT_FALSE(policy.GetAllowNewUsers(&bool_value));
  EXPECT_FALSE(policy.GetMetricsEnabled(&bool_value));
  EXPECT_FALSE(policy.GetReportVersionInfo(&bool_value));
  EXPECT_FALSE(policy.GetReportActivityTimes(&bool_value));
  EXPECT_FALSE(policy.GetReportBootMode(&bool_value));
  EXPECT_FALSE(policy.GetEphemeralSettings(&ephemeral_settings));
  EXPECT_FALSE(policy.GetReleaseChannel(&string_value));
  EXPECT_FALSE(policy.GetUpdateDisabled(&bool_value));
  EXPECT_FALSE(policy.GetTargetVersionPrefix(&string_value));
  EXPECT_FALSE(policy.GetTargetVersionSelector(&string_value));
  EXPECT_FALSE(policy.GetRollbackToTargetVersion(&int_value));
  // RollbackAllowedMilestones has the default value of 4 for enterprise
  // devices.
  ASSERT_TRUE(policy.GetRollbackAllowedMilestones(&int_value));
  EXPECT_EQ(4, int_value);
  EXPECT_FALSE(policy.GetScatterFactorInSeconds(&int64_value));
  EXPECT_FALSE(policy.GetOpenNetworkConfiguration(&string_value));
  EXPECT_FALSE(policy.GetHttpDownloadsEnabled(&bool_value));
  EXPECT_FALSE(policy.GetAuP2PEnabled(&bool_value));
  EXPECT_FALSE(policy.GetAllowKioskAppControlChromeVersion(&bool_value));
  EXPECT_FALSE(policy.GetUsbDetachableWhitelist(&list_device));
  EXPECT_FALSE(policy.GetSecondFactorAuthenticationMode(&int_value));
  EXPECT_FALSE(policy.GetDisallowedTimeIntervals(&intervals));
  EXPECT_FALSE(policy.GetHighestDeviceMinimumVersion(&device_minimum_version));
}

// Verify that the library will correctly recognize and signal missing files.
TEST(PolicyTest, DevicePolicyFailure) {
  LOG(INFO) << "Errors expected.";
  // Try loading non-existing protobuf should fail.
  base::FilePath policy_file(kNonExistingFile);
  base::FilePath key_file(kNonExistingFile);
  PolicyProvider provider;
  provider.SetDevicePolicyForTesting(
      CreateDevicePolicyImpl(std::make_unique<MockInstallAttributesReader>(
                                 cryptohome::SerializedInstallAttributes()),
                             policy_file, key_file, true));

  // Even after reload the policy should still be not loaded.
  ASSERT_FALSE(provider.Reload());
  EXPECT_FALSE(provider.device_policy_is_loaded());
}

// Ensure that signature verification is enforced for a device in vanilla
// enterprise mode.
TEST(PolicyTest, DontSkipSignatureForEnterprise) {
  base::FilePath policy_file(kPolicyFileAllSet);
  base::FilePath key_file(kNonExistingFile);

  PolicyProvider provider;
  provider.SetDevicePolicyForTesting(CreateDevicePolicyImpl(
      std::make_unique<MockInstallAttributesReader>(
          InstallAttributesReader::kDeviceModeEnterprise, true),
      policy_file, key_file, false));
  provider.Reload();

  // Ensure that unverifed policy is not loaded.
  EXPECT_FALSE(provider.device_policy_is_loaded());
}

// Ensure that signature verification is enforced for a device in consumer mode.
TEST(PolicyTest, DontSkipSignatureForConsumer) {
  base::FilePath policy_file(kPolicyFileAllSet);
  base::FilePath key_file(kNonExistingFile);
  cryptohome::SerializedInstallAttributes install_attributes;

  PolicyProvider provider;
  provider.SetDevicePolicyForTesting(CreateDevicePolicyImpl(
      std::make_unique<MockInstallAttributesReader>(install_attributes),
      policy_file, key_file, false));
  provider.Reload();

  // Ensure that unverifed policy is not loaded.
  EXPECT_FALSE(provider.device_policy_is_loaded());
}

// Checks return value of IsConsumerDevice when it's a still in OOBE.
TEST(PolicyTest, DeviceInOobeIsNotConsumerOwned) {
  PolicyProvider provider;
  provider.SetInstallAttributesReaderForTesting(
      std::make_unique<MockInstallAttributesReader>("", false));
  EXPECT_FALSE(provider.IsConsumerDevice());
}

// Checks return value of IsConsumerDevice when it's a consumer device.
TEST(PolicyTest, ConsumerDeviceIsConsumerOwned) {
  PolicyProvider provider;
  provider.SetInstallAttributesReaderForTesting(
      std::make_unique<MockInstallAttributesReader>("", true));
  EXPECT_TRUE(provider.IsConsumerDevice());
}

// Checks return value of IsConsumerDevice when it's an enterprise device.
TEST(PolicyTest, EnterpriseDeviceIsNotConsumerOwned) {
  PolicyProvider provider;
  provider.SetInstallAttributesReaderForTesting(
      std::make_unique<MockInstallAttributesReader>(
          InstallAttributesReader::kDeviceModeEnterprise, true));
  EXPECT_FALSE(provider.IsConsumerDevice());
}

TEST(PolicyTest, LegacyKioskDeviceIsNotConsumerOwned) {
  PolicyProvider provider;
  provider.SetInstallAttributesReaderForTesting(
      std::make_unique<MockInstallAttributesReader>(
          InstallAttributesReader::kDeviceModeLegacyRetail, true));
  EXPECT_FALSE(provider.IsConsumerDevice());
}

TEST(PolicyTest, ConsumerKioskDeviceIsConsumerOwned) {
  PolicyProvider provider;
  provider.SetInstallAttributesReaderForTesting(
      std::make_unique<MockInstallAttributesReader>(
          InstallAttributesReader::kDeviceModeConsumerKiosk, true));
  EXPECT_TRUE(provider.IsConsumerDevice());
}

}  // namespace policy
