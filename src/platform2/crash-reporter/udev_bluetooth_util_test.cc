// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/udev_bluetooth_util.h"

#include <vector>

#include <base/containers/span.h>
#include <base/files/file.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <brillo/strings/string_utils.h>

#include <gtest/gtest.h>

#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

namespace {

constexpr char kCoredumpFlagPath[] = "/run/bluetooth/coredump_disabled";

}  // namespace

class UdevBluetoothUtilTest : public ::testing::Test {
 protected:
  void CreateTestFile(const base::FilePath file_path,
                      const std::vector<std::string>& data) {
    std::string data_str = brillo::string_utils::Join("\n", data);
    // Clear previous test files, if any
    ASSERT_TRUE(base::DeleteFile(file_path));

    ASSERT_EQ(base::WriteFile(file_path, data_str.c_str(), data_str.length()),
              data_str.length());
  }

  base::FilePath dump_path_;
  base::FilePath target_path_;
  base::FilePath data_path_;

 private:
  void SetUp() override {
    CHECK(tmp_dir_.CreateUniqueTempDir());
    paths::SetPrefixForTesting(tmp_dir_.GetPath());
    dump_path_ = tmp_dir_.GetPath().Append("bt_firmware.devcd");
    target_path_ = tmp_dir_.GetPath().Append("bt_firmware.txt");
    data_path_ = tmp_dir_.GetPath().Append("bt_firmware.data");
  }

  base::ScopedTempDir tmp_dir_;
};

// Test a failure case when reading the input coredump file fails.
TEST_F(UdevBluetoothUtilTest, TestInvalidPath) {
  std::string sig;

  EXPECT_FALSE(bluetooth_util::IsBluetoothCoredump(
      dump_path_.ReplaceExtension("invalid")));
  EXPECT_FALSE(bluetooth_util::ProcessBluetoothCoredump(
      dump_path_.ReplaceExtension("invalid"), target_path_, &sig));
  EXPECT_FALSE(bluetooth_util::ReadCrashSig(
      target_path_.ReplaceExtension("invalid"), &sig));
}

// Test a failure case when the crash_sig parameter is NULL.
TEST_F(UdevBluetoothUtilTest, TestNullSig) {
  EXPECT_FALSE(bluetooth_util::ProcessBluetoothCoredump(dump_path_,
                                                        target_path_, nullptr));
}

// Verify feature flag enabled/disabled. The flag name is coredump_disabled.
// So, when disabled is 0, the feature is enabled.
TEST_F(UdevBluetoothUtilTest, TestIsCoredumpEnabled) {
  // Flag file not present, verify feature is disabled.
  EXPECT_FALSE(bluetooth_util::IsCoredumpEnabled());

  // Empty flag file, verify feature is disabled.
  ASSERT_TRUE(test_util::CreateFile(paths::Get(kCoredumpFlagPath), ""));
  EXPECT_FALSE(bluetooth_util::IsCoredumpEnabled());

  // Verify flag disabled case.
  std::vector<std::string> data = {
      "1",
  };
  CreateTestFile(paths::Get(kCoredumpFlagPath), data);
  EXPECT_FALSE(bluetooth_util::IsCoredumpEnabled());

  // Verify flag enabled case.
  data = {
      "0",
  };
  CreateTestFile(paths::Get(kCoredumpFlagPath), data);
  EXPECT_TRUE(bluetooth_util::IsCoredumpEnabled());
}

// Correct header is "Bluetooth devcoredump". Verify IsBluetoothCoredump()
// returns true only when the correct header is detected.
TEST_F(UdevBluetoothUtilTest, TestIsBluetoothCoredump) {
  std::vector<std::string> data = {
      "Bluetooth coredump",
  };
  CreateTestFile(dump_path_, data);
  EXPECT_FALSE(bluetooth_util::IsBluetoothCoredump(dump_path_));

  data = {
      "Bluetooth devcoredumps",
  };
  CreateTestFile(dump_path_, data);
  EXPECT_FALSE(bluetooth_util::IsBluetoothCoredump(dump_path_));

  data = {
      "Bluetooth devcoredump header",
  };
  CreateTestFile(dump_path_, data);
  EXPECT_FALSE(bluetooth_util::IsBluetoothCoredump(dump_path_));

  data = {
      "Bluetooth devcoredump",
  };
  CreateTestFile(dump_path_, data);
  EXPECT_TRUE(bluetooth_util::IsBluetoothCoredump(dump_path_));
}

// In the parsed devcoredump, Driver, Vendor, Controller Name and a PC are
// the erquired fields to generate a crash signature. Verify that an error
// is reported if any of the required keys is missing.
TEST_F(UdevBluetoothUtilTest, TestMissingKeyValue) {
  std::string sig;

  std::vector<std::string> data = {
      "Vendor=TestVen",
      "Controller Name=TestCon",
      "PC=00000000",
  };
  CreateTestFile(target_path_, data);
  EXPECT_FALSE(bluetooth_util::ReadCrashSig(target_path_, &sig));

  data = {
      "Driver=TestDrv",
      "Controller Name=TestCon",
      "PC=00000000",
  };
  CreateTestFile(target_path_, data);
  EXPECT_FALSE(bluetooth_util::ReadCrashSig(target_path_, &sig));

  data = {
      "Driver=TestDrv",
      "Vendor=TestVen",
      "PC=00000000",
  };
  CreateTestFile(target_path_, data);
  EXPECT_FALSE(bluetooth_util::ReadCrashSig(target_path_, &sig));

  data = {
      "Driver=TestDrv",
      "Vendor=TestVen",
      "Controller Name=TestCon",
  };
  CreateTestFile(target_path_, data);
  EXPECT_FALSE(bluetooth_util::ReadCrashSig(target_path_, &sig));
}

// A key-value pair in the parsed devcoredump is of type "<key>=<value>".
// Verify that malformed key-value pairs are not parsed and an error is
// returned.
TEST_F(UdevBluetoothUtilTest, TestInvalidKeyValue) {
  std::string sig;

  // Test missing value in key-value pair
  std::vector<std::string> data = {
      "Driver=",
      "Vendor=TestVen",
      "Controller Name=TestCon",
      "PC=00000000",
  };
  CreateTestFile(target_path_, data);
  EXPECT_FALSE(bluetooth_util::ReadCrashSig(target_path_, &sig));

  // Test malformed key-value pair
  data = {
      "Driver TestDrv",
      "Vendor=TestVen",
      "Controller Name=TestCon",
      "PC=00000000",
  };
  CreateTestFile(target_path_, data);
  EXPECT_FALSE(bluetooth_util::ReadCrashSig(target_path_, &sig));

  // Test malformed key-value pair
  data = {
      "Driver:TestDrv",
      "Vendor=TestVen",
      "Controller Name=TestCon",
      "PC=00000000",
  };
  CreateTestFile(target_path_, data);
  EXPECT_FALSE(bluetooth_util::ReadCrashSig(target_path_, &sig));
}

// Verify if all the required key-value pairs are present and the correct
// crash signature is generated.
TEST_F(UdevBluetoothUtilTest, TestValidParsedData) {
  std::string sig;

  std::vector<std::string> data = {
      "Driver=TestDrv",
      "Vendor=TestVen",
      "Controller Name=TestCon",
      "PC=00000000",
  };
  CreateTestFile(target_path_, data);
  EXPECT_TRUE(bluetooth_util::ReadCrashSig(target_path_, &sig));
  EXPECT_EQ(sig, "bt_firmware-TestDrv-TestVen_TestCon-00000000");
}

// Verify ProcessBluetoothCoredump() invokes bluetooth_devcd_parser binary
// and input devcoredump is parsed successfully.
TEST_F(UdevBluetoothUtilTest, RunAsRoot_TestProcessDump) {
  std::vector<std::string> data = {
      "Bluetooth devcoredump",
      "State: 2",
      "Driver: TestDrv",
      "Vendor: TestVen",
      "Controller Name: TestCon",
      "--- Start dump ---",
      "TestData",
  };
  CreateTestFile(dump_path_, data);

  // Create a file whose existence indicates that this is a developer image.
  ASSERT_TRUE(test_util::CreateFile(paths::Get(paths::kLeaveCoreFile), ""));

  std::string sig;
  EXPECT_TRUE(
      bluetooth_util::ProcessBluetoothCoredump(dump_path_, target_path_, &sig));
  EXPECT_EQ(sig, "bt_firmware-TestDrv-TestVen_TestCon-00000000");

  std::string line;
  ASSERT_TRUE(base::ReadFileToString(data_path_, &line));
  EXPECT_EQ(line, "TestData");
}
