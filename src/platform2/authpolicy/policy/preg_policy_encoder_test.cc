// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <optional>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/json/json_reader.h>
#include <base/strings/stringprintf.h>
#include <components/policy/core/common/registry_dict.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "authpolicy/policy/policy_encoder_helper.h"
#include "authpolicy/policy/preg_policy_encoder.h"
#include "authpolicy/policy/preg_policy_writer.h"
#include "bindings/authpolicy_containers.pb.h"
#include "bindings/chrome_device_policy.pb.h"
#include "bindings/cloud_policy.pb.h"
#include "bindings/policy_constants.h"

namespace em = enterprise_management;

namespace {

constexpr char kPreg1Filename[] = "registry1.pol";
constexpr char kPreg2Filename[] = "registry2.pol";

// Some constants for policy testing.
const bool kPolicyBool = true;
const bool kOtherPolicyBool = false;

const int kPolicyInt = 321;
const int kOtherPolicyInt = 234;

constexpr char kPolicyStr[] = "Str";
constexpr char kOtherPolicyStr[] = "OtherStr";

constexpr char kExtensionId[] = "abcdeFGHabcdefghAbcdefGhabcdEfgh";
constexpr char kOtherExtensionId[] = "ababababcdcdcdcdefefefefghghghgh";
constexpr char kInvalidExtensionId[] = "abcdeFGHabcdefgh";

constexpr char kExtensionPolicy1[] = "Policy1";
constexpr char kExtensionPolicy2[] = "Policy2";
constexpr char kExtensionPolicy3[] = "Policy3";
constexpr char kExtensionPolicy4[] = "Policy4";

}  // namespace

namespace policy {

// Tests basic preg-to-policy encoding and the promises
// ParsePRegFilesIntoUserPolicy and ParsePRegFilesIntoDevicePolicy make.
class PregPolicyEncoderTest : public ::testing::Test {
 public:
  PregPolicyEncoderTest() = default;
  PregPolicyEncoderTest(const PregPolicyEncoderTest&) = delete;
  PregPolicyEncoderTest& operator=(const PregPolicyEncoderTest&) = delete;

  void SetUp() override {
    // Create temp directory for policy files.
    CHECK(base::CreateNewTempDirectory("" /* prefix (ignored) */, &base_path_));

    preg_1_path_ = base_path_.Append(kPreg1Filename);
    preg_2_path_ = base_path_.Append(kPreg2Filename);
  }

  void TearDown() override {
    // Don't not leave no mess behind.
    base::DeletePathRecursively(base_path_);
  }

 protected:
  // Whether policies from the first or the second file win.
  enum WhoWins { FIRST_WINS, SECOND_WINS };

  // Writes two files with policies, encodes them and tests whether policies
  // from the first of the second file 'won' (prevailed). |level1| and |level2|
  // are the policy levels for the two files.
  void TestUserPolicyFileOverride(PolicyLevel level1,
                                  PolicyLevel level2,
                                  WhoWins who_wins) {
    // Write file 1 with some interesting data. Set policy level to level1.
    PRegUserDevicePolicyWriter writer1;
    writer1.AppendBoolean(key::kSearchSuggestEnabled, kOtherPolicyBool, level1);
    writer1.AppendInteger(key::kPolicyRefreshRate, kPolicyInt, level1);
    writer1.AppendString(key::kHomepageLocation, kPolicyStr, level1);
    const std::vector<std::string> apps1 = {"App1", "App2", "App3"};
    writer1.AppendStringList(key::kPinnedLauncherApps, apps1, level1);
    writer1.WriteToFile(preg_1_path_);

    // Write file 2 with the same policies, but different values. Set policy
    // level to level2.
    PRegUserDevicePolicyWriter writer2;
    writer2.AppendBoolean(key::kSearchSuggestEnabled, kPolicyBool, level2);
    writer2.AppendInteger(key::kPolicyRefreshRate, kOtherPolicyInt, level2);
    writer2.AppendString(key::kHomepageLocation, kOtherPolicyStr, level2);
    const std::vector<std::string> apps2 = {"App4", "App5"};
    writer2.AppendStringList(key::kPinnedLauncherApps, apps2, level2);
    writer2.WriteToFile(preg_2_path_);

    // Encode to policy.
    em::CloudPolicySettings policy;
    EXPECT_TRUE(ParsePRegFilesIntoUserPolicy(
        {preg_1_path_, preg_2_path_}, &policy, false /* log_policy_values */));

    bool win_bool = (who_wins == FIRST_WINS ? kOtherPolicyBool : kPolicyBool);
    int win_int = (who_wins == FIRST_WINS ? kPolicyInt : kOtherPolicyInt);
    const std::string& win_string =
        (who_wins == FIRST_WINS ? kPolicyStr : kOtherPolicyStr);
    const auto& win_string_list = (who_wins == FIRST_WINS ? apps1 : apps2);
    PolicyLevel win_level = (who_wins == FIRST_WINS ? level1 : level2);
    em::PolicyOptions::PolicyMode win_mode =
        win_level == POLICY_LEVEL_MANDATORY ? em::PolicyOptions::MANDATORY
                                            : em::PolicyOptions::RECOMMENDED;

    // Check that the expected values prevail.
    EXPECT_TRUE(policy.searchsuggestenabled().has_policy_options());
    EXPECT_EQ(win_mode, policy.searchsuggestenabled().policy_options().mode());
    EXPECT_TRUE(policy.searchsuggestenabled().has_value());
    EXPECT_EQ(win_bool, policy.searchsuggestenabled().value());

    EXPECT_TRUE(policy.policyrefreshrate().has_policy_options());
    EXPECT_EQ(win_mode, policy.policyrefreshrate().policy_options().mode());
    EXPECT_TRUE(policy.policyrefreshrate().has_value());
    EXPECT_EQ(win_int, policy.policyrefreshrate().value());

    EXPECT_TRUE(policy.homepagelocation().has_policy_options());
    EXPECT_EQ(win_mode, policy.homepagelocation().policy_options().mode());
    EXPECT_TRUE(policy.homepagelocation().has_value());
    EXPECT_EQ(win_string, policy.homepagelocation().value());

    EXPECT_TRUE(policy.homepagelocation().has_policy_options());
    EXPECT_EQ(win_mode, policy.pinnedlauncherapps().policy_options().mode());
    EXPECT_TRUE(policy.pinnedlauncherapps().has_value());
    const em::StringList& apps_proto = policy.pinnedlauncherapps().value();
    EXPECT_EQ(apps_proto.entries_size(),
              static_cast<int>(win_string_list.size()));
    for (int n = 0; n < apps_proto.entries_size(); ++n)
      EXPECT_EQ(apps_proto.entries(n), win_string_list.at(n));
  }

  base::FilePath base_path_;
  base::FilePath preg_1_path_;
  base::FilePath preg_2_path_;
};

// Encodes user policies of different types.
TEST_F(PregPolicyEncoderTest, UserPolicyEncodingWorks) {
  // Create a preg file with some interesting data.
  PRegUserDevicePolicyWriter writer;
  writer.AppendBoolean(key::kSearchSuggestEnabled, kPolicyBool);
  writer.AppendInteger(key::kPolicyRefreshRate, kPolicyInt);
  writer.AppendString(key::kHomepageLocation, kPolicyStr);
  const std::vector<std::string> apps = {"App1", "App2"};
  writer.AppendStringList(key::kPinnedLauncherApps, apps);
  writer.WriteToFile(preg_1_path_);

  // Encode preg file into policy.
  em::CloudPolicySettings policy;
  EXPECT_TRUE(ParsePRegFilesIntoUserPolicy({preg_1_path_}, &policy,
                                           false /* log_policy_values */));

  // Check that policy has the same values as we wrote to the file.
  EXPECT_EQ(kPolicyBool, policy.searchsuggestenabled().value());
  EXPECT_EQ(kPolicyInt, policy.policyrefreshrate().value());
  EXPECT_EQ(kPolicyStr, policy.homepagelocation().value());
  const em::StringList& apps_proto = policy.pinnedlauncherapps().value();
  EXPECT_EQ(apps_proto.entries_size(), static_cast<int>(apps.size()));
  for (int n = 0; n < apps_proto.entries_size(); ++n)
    EXPECT_EQ(apps_proto.entries(n), apps.at(n));
}

// Checks that a user GPO later in the list overrides prior GPOs for recommended
// policies.
TEST_F(PregPolicyEncoderTest, UserPolicyRecommendedOverridesRecommended) {
  TestUserPolicyFileOverride(POLICY_LEVEL_RECOMMENDED, POLICY_LEVEL_RECOMMENDED,
                             SECOND_WINS);
}

// Checks that a user GPO later in the list overrides prior GPOs for mandatory
// policies.
TEST_F(PregPolicyEncoderTest, UserPolicyMandatoryOverridesMandatory) {
  TestUserPolicyFileOverride(POLICY_LEVEL_MANDATORY, POLICY_LEVEL_MANDATORY,
                             SECOND_WINS);
}

// Verifies that a mandatory policy is not overridden by a recommended policy.
TEST_F(PregPolicyEncoderTest, UserPolicyRecommendedDoesNotOverrideMandatory) {
  TestUserPolicyFileOverride(POLICY_LEVEL_MANDATORY, POLICY_LEVEL_RECOMMENDED,
                             FIRST_WINS);
}

// Verifies that a mandatory policy overrides a recommended policy.
TEST_F(PregPolicyEncoderTest, UserPolicyMandatoryOverridesRecommended) {
  TestUserPolicyFileOverride(POLICY_LEVEL_RECOMMENDED, POLICY_LEVEL_MANDATORY,
                             SECOND_WINS);
}

// Encodes extension policies of different types.
TEST_F(PregPolicyEncoderTest, ExtensionPolicyEncodingWorks) {
  // Create a preg file with some interesting data.
  PRegExtensionPolicyWriter writer(kExtensionId);
  writer.AppendBoolean(kExtensionPolicy1, kPolicyBool);
  writer.AppendInteger(kExtensionPolicy2, kPolicyInt);
  writer.AppendString(kExtensionPolicy3, kPolicyStr);
  const std::vector<std::string> str_list = {"str1", "str2"};
  writer.AppendStringList(kExtensionPolicy4, str_list);
  writer.WriteToFile(preg_1_path_);

  // Encode preg file into policy.
  ExtensionPolicies policies;
  EXPECT_TRUE(ParsePRegFilesIntoExtensionPolicy({preg_1_path_}, &policies,
                                                false /* log_policy_values */));

  const std::string expected_json = base::StringPrintf(
      "{\"%s\":{\"%s\":1,\"%s\":%i,\"%s\":"
      "\"%s\",\"%s\":{\"1\":\"%s\",\"2\":\"%s\"}}}",
      kKeyMandatoryExtension, kExtensionPolicy1, kExtensionPolicy2, kPolicyInt,
      kExtensionPolicy3, kPolicyStr, kExtensionPolicy4, str_list[0].c_str(),
      str_list[1].c_str());

  // Check that policy has the same values as we wrote to the file.
  ASSERT_EQ(1, policies.size());
  EXPECT_EQ(kExtensionId, policies[0].id());
  EXPECT_EQ(expected_json, policies[0].json_data());
}

// Make sure invalid extension IDs are ignored.
TEST_F(PregPolicyEncoderTest, ExtensionPolicyIgnoresInvalidIds) {
  // Create a preg file with several valid and invalid extension ids.
  PRegExtensionPolicyWriter writer(kExtensionId);
  writer.AppendBoolean(kExtensionPolicy1, kPolicyBool);
  writer.SetKeysForExtensionPolicy(kInvalidExtensionId);
  writer.AppendBoolean(kExtensionPolicy1, kPolicyBool);
  writer.SetKeysForExtensionPolicy(kOtherExtensionId);
  writer.AppendBoolean(kExtensionPolicy1, kPolicyBool);
  writer.WriteToFile(preg_1_path_);

  // Encode preg file into policy.
  ExtensionPolicies policies;
  EXPECT_TRUE(ParsePRegFilesIntoExtensionPolicy({preg_1_path_}, &policies,
                                                false /* log_policy_values */));

  // Extensions with IDs kExtensionId and kOtherExtensionId should be in the
  // output, kInvalidExtensionId shouldn't.
  const std::string expected_json_0 = base::StringPrintf(
      "{\"%s\":{\"%s\":1}}", kKeyMandatoryExtension, kExtensionPolicy1);
  const std::string expected_json_1 = base::StringPrintf(
      "{\"%s\":{\"%s\":1}}", kKeyMandatoryExtension, kExtensionPolicy1);

  ASSERT_EQ(2, policies.size());
  EXPECT_EQ(kOtherExtensionId, policies[0].id());
  EXPECT_EQ(expected_json_0, policies[0].json_data());
  EXPECT_EQ(kExtensionId, policies[1].id());
  EXPECT_EQ(expected_json_1, policies[1].json_data());
}

// Verify that recommended and mandatory policies get encoded separately.
TEST_F(PregPolicyEncoderTest, ExtensionPolicyRecommendedAndMandatory) {
  // Create a preg file with several valid and invalid extension ids.
  PRegExtensionPolicyWriter writer(kExtensionId);
  writer.AppendBoolean(kExtensionPolicy1, kPolicyBool);
  writer.AppendInteger(kExtensionPolicy2, kPolicyInt, POLICY_LEVEL_RECOMMENDED);
  writer.WriteToFile(preg_1_path_);

  // Encode preg file into policy.
  ExtensionPolicies policies;
  EXPECT_TRUE(ParsePRegFilesIntoExtensionPolicy({preg_1_path_}, &policies,
                                                false /* log_policy_values */));

  // Extensions with IDs kExtensionId and kOtherExtensionId should be in the
  // output, kInvalidExtensionId shouldn't.
  const std::string expected_json = base::StringPrintf(
      "{\"%s\":{\"%s\":1},\"%s\":{\"%s\":%i}}", kKeyMandatoryExtension,
      kExtensionPolicy1, kKeyRecommended, kExtensionPolicy2, kPolicyInt);

  ASSERT_EQ(1, policies.size());
  EXPECT_EQ(kExtensionId, policies[0].id());
  EXPECT_EQ(expected_json, policies[0].json_data());
}

// Roundtrips a multi-line JSON dict through a PReg file, and ensures that
// the multi-line string that is roundtripped can be read by JSONReader.
TEST_F(PregPolicyEncoderTest, TestJsonWithNewlinesRoundtrip) {
  PRegUserDevicePolicyWriter writer1;
  const std::vector<std::string> json_with_newlines = {
      "{",
      "  \"TestBool\": true,",
      "  \"TestInt\":",
      "        123456,",
      "  \"TestString\": \"elephant\",",
      "}",
  };
  writer1.AppendMultiString("TestJson", json_with_newlines);
  writer1.WriteToFile(preg_1_path_);

  RegistryDict dict;
  EXPECT_TRUE(LoadPRegFileIntoDict(preg_1_path_, kKeyUserDevice, &dict));
  const std::string& roundtripped_json = dict.GetValue("TestJson")->GetString();
  std::optional<base::Value> json_dict = base::JSONReader::Read(
      roundtripped_json, base::JSON_ALLOW_TRAILING_COMMAS);
  ASSERT_TRUE(json_dict.has_value());
  ASSERT_TRUE(json_dict->is_dict());

  auto test_bool = json_dict->GetDict().FindBool("TestBool");
  ASSERT_TRUE(test_bool.has_value());
  EXPECT_TRUE(*test_bool);

  auto test_int = json_dict->GetDict().FindInt("TestInt");
  ASSERT_TRUE(test_int.has_value());
  EXPECT_EQ(*test_int, 123456);

  auto test_string = json_dict->GetDict().FindString("TestString");
  ASSERT_NE(test_string, nullptr);
  EXPECT_EQ(*test_string, "elephant");
}

// Roundtrips a JSON dict that contains unescaped newlines within a single
// JSON string literal, ensures that the multi-line string that is roundtripped
// can be read by JSONReader.
// This is not strictly valid JSON, but we make sure to allow it anyway since
// pasting certificates into JSON is much easier if they are allowed to contain
// raw newlines, so the admin doesn't have to escape them first.
TEST_F(PregPolicyEncoderTest, TestJsonWithNewlinesInsideStringRoundtrip) {
  PRegUserDevicePolicyWriter writer1;
  const std::vector<std::string> json_with_newlines = {
      "{",
      "  \"TestCertificate\": \"A-B-C-D-E-F-G",
      "H-I-J-K-LMNOP",
      "Q-R-S...T-U-V",
      "W-X...Y-and-Z\"",
      "}",
  };
  writer1.AppendMultiString("TestJson", json_with_newlines);
  writer1.WriteToFile(preg_1_path_);

  RegistryDict dict;
  EXPECT_TRUE(LoadPRegFileIntoDict(preg_1_path_, kKeyUserDevice, &dict));
  const std::string& roundtripped_json = dict.GetValue("TestJson")->GetString();
  std::optional<base::Value> json_dict = base::JSONReader::Read(
      roundtripped_json,
      base::JSON_ALLOW_TRAILING_COMMAS | base::JSON_ALLOW_CONTROL_CHARS);
  ASSERT_TRUE(json_dict.has_value());
  ASSERT_TRUE(json_dict->is_dict());

  auto test_certificate = json_dict->GetDict().FindString("TestCertificate");
  ASSERT_NE(test_certificate, nullptr);
  EXPECT_EQ(*test_certificate,
            "A-B-C-D-E-F-G\nH-I-J-K-LMNOP\nQ-R-S...T-U-V\nW-X...Y-and-Z");
}

}  // namespace policy
