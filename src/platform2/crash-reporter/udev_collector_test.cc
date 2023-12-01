// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/udev_collector.h"

#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/stringprintf.h>
#include <brillo/strings/string_utils.h>
#include <brillo/syslog_logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "crash-reporter/paths.h"
#include "crash-reporter/test_util.h"

using base::FilePath;

namespace {

// Bluetooth devcoredump feature flag path
// TODO(b/203034370): Remove this once the feature is fully launched and the
// feature flag is removed.
constexpr char kBluetoothDumpFlagPath[] = "/run/bluetooth/coredump_disabled";

// Dummy log config file name.
const char kLogConfigFileName[] = "log_config_file";

// Dummy directory for storing device coredumps.
const char kDevCoredumpDirectory[] = "devcoredump";

// A bunch of random rules to put into the dummy log config file.
const char kLogConfigFileContents[] =
    "crash_reporter-udev-collection-change-card0-drm=echo change card0 drm\n"
    "crash_reporter-udev-collection-add-state0-cpu=echo change state0 cpu\n"
    "crash_reporter-udev-collection-devcoredump-iwlwifi=echo devcoredump\n"
    "cros_installer=echo not for udev\n"
    "bt_firmware=echo bluetooth devcoredump\n";

const char kCrashLogFilePattern[] = "*.log.gz";
const char kDevCoredumpFilePattern[] = "*.devcore.gz";
const char kBluetoothCoredumpFilePattern[] = "bt_firmware.*";

// Dummy content for device coredump data file.
const char kDevCoredumpDataContents[] = "coredump";

// Driver name for a coredump that should not be collected:
const char kNoCollectDriverName[] = "iwlwifi";

// Driver name for a coredump that should be collected:
const char kCollectedDriverName[] = "msm";

// Returns the number of files found in the given path that matches the
// specified file name pattern.
int GetNumFiles(const FilePath& path, const std::string& file_pattern) {
  base::FileEnumerator enumerator(path, false, base::FileEnumerator::FILES,
                                  file_pattern);
  int num_files = 0;
  for (FilePath file_path = enumerator.Next(); !file_path.value().empty();
       file_path = enumerator.Next()) {
    num_files++;
  }
  return num_files;
}

}  // namespace

class UdevCollectorMock : public UdevCollector {
 public:
  MOCK_METHOD(void, SetUpDBus, (), (override));
};

class UdevCollectorTest : public ::testing::Test {
 protected:
  base::ScopedTempDir temp_dir_generator_;

  void HandleCrash(const std::string& udev_event) {
    collector_.HandleCrash(udev_event);
  }

  void GenerateDevCoredump(const std::string& device_name,
                           const std::string& driver_name) {
    // Generate coredump data file.
    ASSERT_TRUE(CreateDirectory(FilePath(
        base::StringPrintf("%s/%s", collector_.dev_coredump_directory_.c_str(),
                           device_name.c_str()))));
    FilePath data_path = FilePath(base::StringPrintf(
        "%s/%s/data", collector_.dev_coredump_directory_.c_str(),
        device_name.c_str()));
    ASSERT_TRUE(test_util::CreateFile(data_path, kDevCoredumpDataContents));
    // Generate uevent file for failing device.
    ASSERT_TRUE(CreateDirectory(FilePath(base::StringPrintf(
        "%s/%s/failing_device", collector_.dev_coredump_directory_.c_str(),
        device_name.c_str()))));
    FilePath uevent_path = FilePath(base::StringPrintf(
        "%s/%s/failing_device/uevent",
        collector_.dev_coredump_directory_.c_str(), device_name.c_str()));
    ASSERT_TRUE(
        test_util::CreateFile(uevent_path, "DRIVER=" + driver_name + "\n"));
  }

  void SetUpCollector(UdevCollectorMock* collector) {
    EXPECT_CALL(*collector, SetUpDBus()).WillRepeatedly(testing::Return());
    collector->Initialize(false);

    collector->log_config_path_ = log_config_path_;
    collector->set_crash_directory_for_test(temp_dir_generator_.GetPath());

    FilePath dev_coredump_path =
        temp_dir_generator_.GetPath().Append(kDevCoredumpDirectory);
    collector->dev_coredump_directory_ = dev_coredump_path.value();
  }

 private:
  void SetUp() override {
    ASSERT_TRUE(temp_dir_generator_.CreateUniqueTempDir());
    log_config_path_ = temp_dir_generator_.GetPath().Append(kLogConfigFileName);

    SetUpCollector(&collector_);
    // Write to a dummy log config file.
    ASSERT_TRUE(
        test_util::CreateFile(log_config_path_, kLogConfigFileContents));
    brillo::ClearLog();
  }

  FilePath log_config_path_;
  UdevCollectorMock collector_;
};

TEST_F(UdevCollectorTest, TestNoMatch) {
  // No rule should match this.
  HandleCrash("ACTION=change:KERNEL=foo:SUBSYSTEM=bar");
  EXPECT_EQ(0,
            GetNumFiles(temp_dir_generator_.GetPath(), kCrashLogFilePattern));
}

TEST_F(UdevCollectorTest, TestMatches) {
  // Try multiple udev events in sequence.  The number of log files generated
  // should increase.
  HandleCrash("ACTION=change:KERNEL=card0:SUBSYSTEM=drm");
  EXPECT_EQ(1,
            GetNumFiles(temp_dir_generator_.GetPath(), kCrashLogFilePattern));

  // Each collector is only allowed to handle one crash, so create a second
  // collector for the second crash.
  UdevCollectorMock second_collector;
  SetUpCollector(&second_collector);
  second_collector.HandleCrash("ACTION=add:KERNEL=state0:SUBSYSTEM=cpu");
  EXPECT_EQ(2,
            GetNumFiles(temp_dir_generator_.GetPath(), kCrashLogFilePattern));
}

TEST_F(UdevCollectorTest, TestDevCoredump) {
  GenerateDevCoredump("devcd0", kNoCollectDriverName);
  HandleCrash("ACTION=add:KERNEL_NUMBER=0:SUBSYSTEM=devcoredump");
  // IsDeveloperImage() returns false while running this test so devcoredumps
  // will not be added to the crash directory.
  EXPECT_EQ(
      0, GetNumFiles(temp_dir_generator_.GetPath(), kDevCoredumpFilePattern));
  GenerateDevCoredump("devcd1", kNoCollectDriverName);
  // Each collector is only allowed to handle one crash, so create a second
  // collector for the second crash.
  UdevCollectorMock second_collector;
  SetUpCollector(&second_collector);
  second_collector.HandleCrash(
      "ACTION=add:KERNEL_NUMBER=1:SUBSYSTEM=devcoredump");
  EXPECT_EQ(
      0, GetNumFiles(temp_dir_generator_.GetPath(), kDevCoredumpFilePattern));
}

TEST_F(UdevCollectorTest, TestCollectedDevCoredump) {
  // One more test, this time for the case of a devcoredump that should be
  // collected in all builds:
  GenerateDevCoredump("devcd2", kCollectedDriverName);
  UdevCollectorMock third_collector;
  SetUpCollector(&third_collector);
  third_collector.HandleCrash(
      "ACTION=add:KERNEL_NUMBER=2:SUBSYSTEM=devcoredump");
  EXPECT_EQ(
      1, GetNumFiles(temp_dir_generator_.GetPath(), kDevCoredumpFilePattern));
  // Check for the expected crash signature:
  base::FilePath meta_path;
  std::string meta_pattern = "devcoredump_";
  meta_pattern += kCollectedDriverName;
  meta_pattern += ".*.meta";
  EXPECT_TRUE(test_util::DirectoryHasFileWithPattern(
      temp_dir_generator_.GetPath(), meta_pattern, &meta_path));
  std::string meta_contents;
  EXPECT_TRUE(base::ReadFileToString(meta_path, &meta_contents));
  std::string expected_sig = "sig=crash_reporter-udev-collection-devcoredump-";
  expected_sig += kCollectedDriverName;
  EXPECT_THAT(meta_contents, testing::HasSubstr(expected_sig));
}

TEST_F(UdevCollectorTest, RunAsRoot_TestValidBluetoothDevCoredump) {
  std::string device_name = "devcd0";
  GenerateDevCoredump(device_name, kNoCollectDriverName);

  FilePath data_path =
      FilePath(base::StringPrintf("%s/%s/data",
                                  temp_dir_generator_.GetPath()
                                      .Append(kDevCoredumpDirectory)
                                      .value()
                                      .c_str(),
                                  device_name.c_str()));

  std::vector<std::string> data = {
      "Bluetooth devcoredump",
      "State: 2",
      "Driver: TestDrv",
      "Vendor: TestVen",
      "Controller Name: TestCon",
      "--- Start dump ---",
      "TestData",
  };
  std::string data_str = brillo::string_utils::Join("\n", data);
  ASSERT_EQ(base::WriteFile(data_path, data_str.c_str(), data_str.length()),
            data_str.length());

  ASSERT_TRUE(test_util::CreateFile(paths::Get(kBluetoothDumpFlagPath), "0"));

  HandleCrash("ACTION=add:KERNEL_NUMBER=0:SUBSYSTEM=devcoredump");
  EXPECT_EQ(3, GetNumFiles(temp_dir_generator_.GetPath(),
                           kBluetoothCoredumpFilePattern));
}

TEST_F(UdevCollectorTest, RunAsRoot_TestInvalidBluetoothDevCoredump) {
  std::string device_name = "devcd1";
  GenerateDevCoredump(device_name, kNoCollectDriverName);

  FilePath data_path =
      FilePath(base::StringPrintf("%s/%s/data",
                                  temp_dir_generator_.GetPath()
                                      .Append(kDevCoredumpDirectory)
                                      .value()
                                      .c_str(),
                                  device_name.c_str()));

  // Incomplete bluetooth devcoredump header, parsing should fail and no output
  // files should get generated.
  std::vector<std::string> data = {
      "Bluetooth devcoredump",
      "State: 2",
      "Driver: TestDrv",
      "Vendor: TestVen",
  };
  std::string data_str = brillo::string_utils::Join("\n", data);
  ASSERT_EQ(base::WriteFile(data_path, data_str.c_str(), data_str.length()),
            data_str.length());

  ASSERT_TRUE(test_util::CreateFile(paths::Get(kBluetoothDumpFlagPath), "0"));

  HandleCrash("ACTION=add:KERNEL_NUMBER=1:SUBSYSTEM=devcoredump");
  EXPECT_EQ(0, GetNumFiles(temp_dir_generator_.GetPath(),
                           kBluetoothCoredumpFilePattern));
}

// TODO(sque, crosbug.com/32238) - test wildcard cases, multiple identical udev
// events.
