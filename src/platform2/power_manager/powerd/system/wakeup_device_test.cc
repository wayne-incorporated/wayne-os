// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/wakeup_device.h"

#include <limits>
#include <memory>
#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <gtest/gtest.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {
namespace {

// Creates and writes |val| to |sys_path|. Also creates all necessary parent
// directories.
void CreateDirectoryAndWriteFile(const base::FilePath& sys_path,
                                 const std::string& val) {
  ASSERT_TRUE(base::CreateDirectory(sys_path.DirName()));
  CHECK_EQ(base::WriteFile(sys_path, val.c_str(), val.length()), val.length());
}

}  // namespace

class WakeupDeviceTest : public TestEnvironment {
 public:
  WakeupDeviceTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    std::string kTestSysPath = "sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/";
    wakeup_device_path_ = temp_dir_.GetPath().Append(kTestSysPath);

    wakeup_attr_path_ = wakeup_device_path_.Append(kPowerWakeup);
    CreateDirectoryAndWriteFile(wakeup_attr_path_, "enabled");
    std::string random_events_count_dir = "wakeup45";
    event_count_attr_path_ =
        wakeup_device_path_.Append(WakeupDevice::kWakeupDir)
            .Append(random_events_count_dir)
            .Append(WakeupDevice::kPowerEventCountPath);

    wakeup_device_ = WakeupDevice::CreateWakeupDevice(wakeup_device_path_);
    CHECK(wakeup_device_);
  }
  WakeupDeviceTest(const WakeupDeviceTest&) = delete;
  WakeupDeviceTest& operator=(const WakeupDeviceTest&) = delete;

  ~WakeupDeviceTest() override = default;

 protected:
  std::unique_ptr<WakeupDeviceInterface> wakeup_device_;
  base::ScopedTempDir temp_dir_;

  base::FilePath wakeup_device_path_;
  base::FilePath wakeup_attr_path_;
  base::FilePath event_count_attr_path_;
};

// An incremented event_count value should result in proper identification of
// wakeup device.
TEST_F(WakeupDeviceTest, TestWakeupCountIncrement) {
  const std::string kEventCountBeforeSuspendStr = "1";
  CreateDirectoryAndWriteFile(event_count_attr_path_,
                              kEventCountBeforeSuspendStr);
  wakeup_device_->PrepareForSuspend();
  const std::string kEventCountAfterResumeStr = "2";
  CreateDirectoryAndWriteFile(event_count_attr_path_,
                              kEventCountAfterResumeStr);
  wakeup_device_->HandleResume();
  EXPECT_TRUE(wakeup_device_->CausedLastWake());
}

// A overflow of event_count value should result in proper identification of
// wakeup device.
TEST_F(WakeupDeviceTest, TestWakeupCountOverflow) {
  const std::string kEventCountBeforeSuspendStr =
      base::NumberToString(std::numeric_limits<uint64_t>::max());
  CreateDirectoryAndWriteFile(event_count_attr_path_,
                              kEventCountBeforeSuspendStr);
  wakeup_device_->PrepareForSuspend();
  const std::string kEventCountAfterResumeStr =
      base::NumberToString(std::numeric_limits<uint64_t>::max() + 1);
  CreateDirectoryAndWriteFile(event_count_attr_path_,
                              kEventCountAfterResumeStr);
  wakeup_device_->HandleResume();
  EXPECT_TRUE(wakeup_device_->CausedLastWake());
}

// A empty event_count file should result in proper identification of
// wakeup device.
TEST_F(WakeupDeviceTest, TestEmptyWakeupCountFile) {
  const std::string kEventCountBeforeSuspendStr = "";
  CreateDirectoryAndWriteFile(event_count_attr_path_,
                              kEventCountBeforeSuspendStr);
  wakeup_device_->PrepareForSuspend();
  const std::string kEventCountAfterResumeStr = "2";
  CreateDirectoryAndWriteFile(event_count_attr_path_,
                              kEventCountAfterResumeStr);
  wakeup_device_->HandleResume();
  EXPECT_TRUE(wakeup_device_->CausedLastWake());
}

// Failure to read the event_count before suspend should not mark the device as
// wake source.
TEST_F(WakeupDeviceTest, TestWakeupCountReadFailBeforeSuspend) {
  wakeup_device_->PrepareForSuspend();
  const std::string kEventCountAfterResumeStr = base::NumberToString(1);
  CreateDirectoryAndWriteFile(event_count_attr_path_,
                              kEventCountAfterResumeStr);
  wakeup_device_->HandleResume();
  EXPECT_FALSE(wakeup_device_->CausedLastWake());
}

// Failure to read the event_count after resume should not mark the device as
// wake source.
TEST_F(WakeupDeviceTest, TestWakeupCountReadFailAfterResume) {
  const std::string kEventCountBeforeSuspendStr = "1";
  CreateDirectoryAndWriteFile(event_count_attr_path_,
                              kEventCountBeforeSuspendStr);
  wakeup_device_->PrepareForSuspend();
  ASSERT_TRUE(base::DeleteFile(event_count_attr_path_));
  wakeup_device_->HandleResume();
  EXPECT_FALSE(wakeup_device_->CausedLastWake());
}

}  // namespace power_manager::system
