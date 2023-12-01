// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdint.h>
#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <base/files/memory_mapped_file.h>
#include <base/files/scoped_temp_dir.h>
#include <testing/gmock/include/gmock/gmock.h>
#include <testing/gtest/include/gtest/gtest.h>

#include "policy_utils/policy_writer.h"

using base::File;
using base::FilePath;
using policy_utils::PolicyWriter;
using testing::MatchesRegex;

class PolicyWriterTest : public ::testing::Test {
 public:
  PolicyWriterTest() = default;
  PolicyWriterTest(const PolicyWriterTest&) = delete;
  PolicyWriterTest& operator=(const PolicyWriterTest&) = delete;

  void SetUp() override {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    dest_dir_path_ = temp_dir_.GetPath();
    policy_writer_ = new PolicyWriter(dest_dir_path_.value());
  }

  void TearDown() override {
    delete policy_writer_;
    policy_writer_ = nullptr;
  }

  const FilePath& dest_dir_path() { return dest_dir_path_; }

  PolicyWriter* policy_writer() { return policy_writer_; }

 private:
  base::ScopedTempDir temp_dir_;
  FilePath dest_dir_path_;
  PolicyWriter* policy_writer_ = nullptr;
};

// Test setting and clearing policy DeviceAllowBluetooth.
TEST_F(PolicyWriterTest, DeviceAllowBluetooth) {
  const char kPolicyDeviceAllowBluetoothFileName[] =
      "device_allow_bluetooth.json";

  // Verify that setting policy DeviceAllowBluetooth create a json file with the
  // correct name.
  {
    EXPECT_TRUE(policy_writer()->SetDeviceAllowBluetooth(true));
    FilePath json_file =
        dest_dir_path().Append(kPolicyDeviceAllowBluetoothFileName);
    EXPECT_TRUE(base::PathExists(json_file));
  }

  // Verify that json data as something like "DeviceAllowBlueTooth: true".
  {
    ASSERT_TRUE(policy_writer()->SetDeviceAllowBluetooth(true));

    FilePath json_file =
        dest_dir_path().Append(kPolicyDeviceAllowBluetoothFileName);
    ASSERT_TRUE(base::PathExists(json_file));

    std::string json_string;
    EXPECT_TRUE(base::ReadFileToString(json_file, &json_string));
    EXPECT_GT(json_string.length(), 0);
    EXPECT_THAT(json_string, MatchesRegex(".*DeviceAllowBluetooth.*:.*true.*"));
  }

  // Same as above but with "DeviceAllowBlueTooth: false".
  {
    ASSERT_TRUE(policy_writer()->SetDeviceAllowBluetooth(false));

    FilePath json_file =
        dest_dir_path().Append(kPolicyDeviceAllowBluetoothFileName);
    ASSERT_TRUE(base::PathExists(json_file));

    std::string json_string;
    EXPECT_TRUE(base::ReadFileToString(json_file, &json_string));
    EXPECT_GT(json_string.length(), 0);
    EXPECT_THAT(json_string,
                MatchesRegex(".*DeviceAllowBluetooth.*:.*false.*"));
  }

  // Verify that clearing the policy removes the json file.
  {
    EXPECT_TRUE(policy_writer()->SetDeviceAllowBluetooth(false));
    EXPECT_TRUE(policy_writer()->ClearDeviceAllowBluetooth());

    FilePath json_file =
        dest_dir_path().Append(kPolicyDeviceAllowBluetoothFileName);
    ASSERT_FALSE(base::PathExists(json_file));
  }
}
