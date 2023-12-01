// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/wakeup_source_identifier.h"

#include <memory>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/strings/string_util.h>
#include <base/strings/string_number_conversions.h>
#include <gtest/gtest.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/util.h"
#include "power_manager/powerd/system/udev_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {
namespace {

const char kRandomEventCountPath[] = "wakeup/wakeup45/event_count";
const char kTestSysPath[] = "sys/devices/pci0000:00/0000:00:14.0/usb1/1-2/";

// Creates |file_path|. Also creates all necessary parent directories.
void CreateFile(const base::FilePath& file_path) {
  ASSERT_TRUE(base::CreateDirectory(file_path.DirName()));
  CHECK_EQ(base::WriteFile(file_path, "", 0), 0);
}

void CreatePowerWakeupAttrInDir(const base::FilePath& dir_path) {
  const base::FilePath wakeup_path = dir_path.Append(kPowerWakeup);
  CreateFile(wakeup_path);
}

void CreateEventCountAttrInSys(const base::FilePath& dir_path) {
  const base::FilePath event_count_path =
      dir_path.Append(kRandomEventCountPath);
  CreateFile(event_count_path);
  // By default set the event count to 0
  ASSERT_TRUE(util::WriteInt64File(event_count_path, 0));
}

void IncrementEventCount(const base::FilePath& dir_path) {
  const base::FilePath event_count_path =
      dir_path.Append(kRandomEventCountPath);

  std::string event_count_str;
  ASSERT_TRUE(base::ReadFileToString(event_count_path, &event_count_str));
  base::TrimWhitespaceASCII(event_count_str, base::TRIM_TRAILING,
                            &event_count_str);
  int64_t current_count;
  ASSERT_TRUE(base::StringToInt64(event_count_str, &current_count));

  ASSERT_TRUE(util::WriteInt64File(event_count_path, current_count + 1));
}

class WakeupSourceIdentifierTest : public TestEnvironment {
 public:
  WakeupSourceIdentifierTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    wakeup_device_path_ = temp_dir_.GetPath().Append(kTestSysPath);
    CreatePowerWakeupAttrInDir(wakeup_device_path_);
    CreateEventCountAttrInSys(wakeup_device_path_);
    wakeup_source_identifier_ =
        std::make_unique<system::WakeupSourceIdentifier>(&udev_);
  }

 protected:
  void SendInputUdevEvent(const UdevEvent::Action action,
                          const std::string& input_name,
                          const base::FilePath& wakeup_path) {
    UdevDeviceInfo input_device_info;
    input_device_info.subsystem = kInputUdevSubsystem;
    input_device_info.sysname = input_name;
    input_device_info.wakeup_device_path = wakeup_path;

    UdevEvent event;
    event.action = action;
    event.device_info = input_device_info;
    udev_.NotifySubsystemObservers(event);
  }

  UdevStub udev_;
  std::unique_ptr<WakeupSourceIdentifier> wakeup_source_identifier_;
  base::ScopedTempDir temp_dir_;
  base::FilePath wakeup_device_path_;
};

TEST_F(WakeupSourceIdentifierTest, TestWakeDueToInputDevice) {
  // Add first input with |wakeup_device_path_|
  SendInputUdevEvent(UdevEvent::Action::ADD, "input1", wakeup_device_path_);
  // Now let us suspend and increment the event count.
  wakeup_source_identifier_->PrepareForSuspendRequest();
  IncrementEventCount(wakeup_device_path_);
  wakeup_source_identifier_->HandleResume();
  EXPECT_TRUE(wakeup_source_identifier_->InputDeviceCausedLastWake());
}

TEST_F(WakeupSourceIdentifierTest, TestAddAndRemoveInputDevice) {
  // Add first input with |wakeup_device_path_|
  SendInputUdevEvent(UdevEvent::Action::ADD, "input1", wakeup_device_path_);
  SendInputUdevEvent(UdevEvent::Action::REMOVE, "input1", wakeup_device_path_);

  // Now let us suspend and increment the event count.
  wakeup_source_identifier_->PrepareForSuspendRequest();
  IncrementEventCount(wakeup_device_path_);
  wakeup_source_identifier_->HandleResume();
  EXPECT_FALSE(wakeup_source_identifier_->InputDeviceCausedLastWake());
}

TEST_F(WakeupSourceIdentifierTest, TestMultipleInputDevicesWithSameWakePath) {
  // Add first input with |wakeup_device_path_|
  SendInputUdevEvent(UdevEvent::Action::ADD, "input1", wakeup_device_path_);
  SendInputUdevEvent(UdevEvent::Action::ADD, "input2", wakeup_device_path_);
  SendInputUdevEvent(UdevEvent::Action::REMOVE, "input1", wakeup_device_path_);
  // Now let us suspend and increment the event count.
  wakeup_source_identifier_->PrepareForSuspendRequest();
  IncrementEventCount(wakeup_device_path_);
  wakeup_source_identifier_->HandleResume();
  EXPECT_TRUE(wakeup_source_identifier_->InputDeviceCausedLastWake());
}

}  // namespace
}  // namespace power_manager::system
