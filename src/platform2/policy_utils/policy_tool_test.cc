// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <memory>
#include <string>
#include <utility>

#include <base/command_line.h>
#include <base/files/file_util.h>
#include <base/files/memory_mapped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <testing/gmock/include/gmock/gmock.h>
#include <testing/gtest/include/gtest/gtest.h>

#include "policy_utils/policy_tool.h"

using base::CommandLine;
using base::File;
using base::FilePath;
using policy_utils::PolicyTool;
using testing::MatchesRegex;

class PolicyToolTest : public ::testing::Test {
 public:
  PolicyToolTest() = default;
  PolicyToolTest(const PolicyToolTest&) = delete;
  PolicyToolTest& operator=(const PolicyToolTest&) = delete;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    dest_dir_path_ = temp_dir_.GetPath();
    policy_tool_.reset(new PolicyTool(dest_dir_path_.value()));
  }

  const FilePath& dest_dir_path() { return dest_dir_path_; }

  PolicyTool* policy_tool() { return policy_tool_.get(); }

 private:
  base::ScopedTempDir temp_dir_;
  FilePath dest_dir_path_;
  std::unique_ptr<PolicyTool> policy_tool_;
};

// Test setting and clearing policy DeviceAllowBluetooth.
TEST_F(PolicyToolTest, DeviceAllowBluetooth) {
  const char kPolicyDeviceAllowBluetoothFileName[] =
      "device_allow_bluetooth.json";

  // Verify that "Set DeviceAllowBluetooth true" sets policy to true through
  // JSON file.
  {
    const char* argv[] = {"app_name", "set", "DeviceAllowBluetooth", "true"};
    CommandLine cl(4, argv);

    EXPECT_TRUE(policy_tool()->DoCommand(cl.GetArgs()));
    FilePath json_file =
        dest_dir_path().Append(kPolicyDeviceAllowBluetoothFileName);
    EXPECT_TRUE(base::PathExists(json_file));

    std::string json_string;
    EXPECT_TRUE(base::ReadFileToString(json_file, &json_string));
    EXPECT_GT(json_string.length(), 0);
    EXPECT_THAT(json_string, MatchesRegex(".*DeviceAllowBluetooth.*:.*true.*"));
  }

  // Verify that "clear DeviceAllowBluetooth" removes the policy override.
  {
    const char* argv[] = {"app_name", "clear", "DeviceAllowBluetooth"};
    CommandLine cl(3, argv);

    EXPECT_TRUE(policy_tool()->DoCommand(cl.GetArgs()));
    FilePath json_file =
        dest_dir_path().Append(kPolicyDeviceAllowBluetoothFileName);
    EXPECT_FALSE(base::PathExists(json_file));
  }

  // Verify that "Set DeviceAllowBluetooth false" sets policy to false through
  // JSON file.
  {
    const char* argv[] = {"app_name", "set", "DeviceAllowBluetooth", "false"};
    CommandLine cl(4, argv);

    EXPECT_TRUE(policy_tool()->DoCommand(cl.GetArgs()));
    FilePath json_file =
        dest_dir_path().Append(kPolicyDeviceAllowBluetoothFileName);
    EXPECT_TRUE(base::PathExists(json_file));

    std::string json_string;
    EXPECT_TRUE(base::ReadFileToString(json_file, &json_string));
    EXPECT_GT(json_string.length(), 0);
    EXPECT_THAT(json_string,
                MatchesRegex(".*DeviceAllowBluetooth.*:.*false.*"));
  }
}
