// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/policy/bluetooth_controller.h"

#include <memory>
#include <string>

#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_piece.h>
#include <featured/fake_platform_features.h>
#include <gtest/gtest.h>

#include "power_manager/powerd/system/dbus_wrapper_stub.h"
#include "power_manager/powerd/system/udev_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::policy {

class BluetoothControllerTest : public TestEnvironment {
 public:
  BluetoothControllerTest() = default;
  BluetoothControllerTest(const BluetoothControllerTest&) = delete;
  BluetoothControllerTest& operator=(const BluetoothControllerTest&) = delete;

 protected:
  static constexpr char kBtDeepDir[] = "usb/1-6/1-6:1.0/bluetooth/hci0";
  static constexpr char kBtTaggedDevice[] = "input/1:2:3:4/event17";
  static constexpr char kBtWakeDir[] = "usb/1-6/";
  static constexpr char kPowerDir[] = "power";
  static constexpr char kValidDirPrefix[] = "valid";
  static constexpr char kInvalidDirPrefix[] = "invalid";
  static constexpr char kErrorContents[] = "file-read-error";
  static constexpr char kRestoreTestContents[] = "restore-to-this";

  void Init(bool with_existing_valid_device = false,
            bool with_autosuspend_feature_enabled = false) {
    PrepareTestFiles();
    controller_ = std::make_unique<BluetoothController>();
    if (with_existing_valid_device) {
      system::UdevDeviceInfo info = ConstructDeviceInfo(true);
      udev_.AddSubsystemDevice(BluetoothController::kUdevSubsystemBluetooth,
                               info, {"/dev/foobar"});
    }
    platform_features_ =
        std::make_unique<feature::FakePlatformFeatures>(dbus_wrapper_.GetBus());
    platform_features_->SetEnabled(
        BluetoothController::kLongAutosuspendFeatureName,
        with_autosuspend_feature_enabled);
    controller_->Init(&udev_, platform_features_.get(), &dbus_wrapper_);
  }

  void PrepareTestFiles() {
    base::FilePath unused;
    ASSERT_TRUE(base::CreateNewTempDirectory(unused.value(), &file_prefix_));

    base::FilePath valid_deep_dir =
        file_prefix_.Append(kValidDirPrefix).Append(kBtDeepDir);
    base::FilePath valid_power_dir = file_prefix_.Append(kValidDirPrefix)
                                         .Append(kBtWakeDir)
                                         .Append(kPowerDir);
    base::FilePath valid_control_file =
        file_prefix_.Append(kValidDirPrefix)
            .Append(kBtWakeDir)
            .Append(BluetoothController::kAutosuspendSysattr);
    base::FilePath valid_delay_file =
        file_prefix_.Append(kValidDirPrefix)
            .Append(kBtWakeDir)
            .Append(BluetoothController::kAutosuspendDelaySysattr);

    base::FilePath invalid_deep_dir =
        file_prefix_.Append(kInvalidDirPrefix).Append(kBtDeepDir);

    base::StringPiece autosuspend_enabled(
        BluetoothController::kAutosuspendEnabled);
    base::StringPiece default_autosuspend_delay(
        BluetoothController::kDefaultAutosuspendTimeout);

    // Add all directories including the "power/control" file in the valid path.
    ASSERT_TRUE(base::CreateDirectory(valid_deep_dir));
    ASSERT_TRUE(base::CreateDirectory(valid_power_dir));
    ASSERT_TRUE(base::WriteFile(valid_control_file, autosuspend_enabled));
    ASSERT_TRUE(base::WriteFile(valid_delay_file, default_autosuspend_delay));
    ASSERT_TRUE(base::CreateDirectory(invalid_deep_dir));
  }

  system::UdevDeviceInfo ConstructDeviceInfo(bool valid) {
    base::FilePath syspath =
        file_prefix_.Append(valid ? kValidDirPrefix : kInvalidDirPrefix)
            .Append(kBtDeepDir);
    base::FilePath wake_path =
        file_prefix_.Append(valid ? kValidDirPrefix : kInvalidDirPrefix)
            .Append(kBtWakeDir);

    system::UdevDeviceInfo info = {
        BluetoothController::kUdevSubsystemBluetooth,
        BluetoothController::kUdevDevtypeHost, "",
        std::string(syspath.value().data(), syspath.value().size()), wake_path};

    return info;
  }

  void SendUdevEvent(system::UdevEvent::Action action, bool valid) {
    system::UdevDeviceInfo device_info = ConstructDeviceInfo(valid);
    udev_.NotifySubsystemObservers({device_info, action});
  }

  void SendTaggedDeviceChange(const std::string& syspath_suffix) {
    base::FilePath syspath = file_prefix_.Append(kValidDirPrefix)
                                 .Append(kBtTaggedDevice)
                                 .Append(syspath_suffix);
    base::FilePath wake_path =
        file_prefix_.Append(kValidDirPrefix).Append(kBtWakeDir);

    udev_.TaggedDeviceChanged(syspath.value(), wake_path, /*tags=*/"");
  }

  void SendTaggedDeviceRemoved(const std::string& syspath_suffix) {
    base::FilePath syspath = file_prefix_.Append(kValidDirPrefix)
                                 .Append(kBtTaggedDevice)
                                 .Append(syspath_suffix);

    udev_.TaggedDeviceRemoved(syspath.value());
  }

  void SetPowerdRoleOn(const std::string& syspath_suffix,
                       const std::string& role) {
    base::FilePath syspath = file_prefix_.Append(kValidDirPrefix)
                                 .Append(kBtTaggedDevice)
                                 .Append(syspath_suffix);

    udev_.SetPowerdRole(syspath.value(), role);
  }

  std::string GetControlPathContents(bool valid) {
    std::string out;
    base::FilePath filepath =
        file_prefix_.Append(valid ? kValidDirPrefix : kInvalidDirPrefix)
            .Append(kBtWakeDir)
            .Append(BluetoothController::kAutosuspendSysattr);

    if (!base::ReadFileToString(filepath, &out)) {
      out = kErrorContents;
    }

    return out;
  }

  std::string GetDelayPathContents() {
    std::string out;
    base::FilePath filepath =
        file_prefix_.Append(kValidDirPrefix)
            .Append(kBtWakeDir)
            .Append(BluetoothController::kAutosuspendDelaySysattr);

    if (!base::ReadFileToString(filepath, &out)) {
      out = kErrorContents;
    }

    return out;
  }

  bool WriteToControlPath(bool valid, const base::StringPiece& contents) {
    base::FilePath filepath =
        file_prefix_.Append(valid ? kValidDirPrefix : kInvalidDirPrefix)
            .Append(kBtWakeDir)
            .Append(BluetoothController::kAutosuspendSysattr);
    return base::WriteFile(filepath, contents);
  }

  base::FilePath file_prefix_;
  system::DBusWrapperStub dbus_wrapper_;
  system::UdevStub udev_;
  std::unique_ptr<BluetoothController> controller_;
  std::unique_ptr<feature::FakePlatformFeatures> platform_features_;
};

TEST_F(BluetoothControllerTest, AutosuspendQuirkApplied) {
  Init();

  // Valid path should start with autosuspend enabled
  SendUdevEvent(system::UdevEvent::Action::ADD, true);
  EXPECT_EQ(GetControlPathContents(true),
            BluetoothController::kAutosuspendEnabled);

  // Disable when applying quirk and enable when unapplying quirk.
  controller_->ApplyAutosuspendQuirk();
  EXPECT_EQ(GetControlPathContents(true),
            BluetoothController::kAutosuspendDisabled);
  controller_->UnapplyAutosuspendQuirk();
  EXPECT_EQ(GetControlPathContents(true),
            BluetoothController::kAutosuspendEnabled);
}

TEST_F(BluetoothControllerTest, RestoresCorrectValue) {
  Init();

  base::StringPiece autosuspend_restore_to(
      BluetoothControllerTest::kRestoreTestContents);
  // Valid path should start with autosuspend enabled. Change it afterwards.
  SendUdevEvent(system::UdevEvent::Action::ADD, true);
  EXPECT_EQ(GetControlPathContents(true),
            BluetoothController::kAutosuspendEnabled);
  ASSERT_TRUE(WriteToControlPath(true, autosuspend_restore_to));

  // Disable when applying quirk and restore when unapplying quirk.
  controller_->ApplyAutosuspendQuirk();
  EXPECT_EQ(GetControlPathContents(true),
            BluetoothController::kAutosuspendDisabled);
  controller_->UnapplyAutosuspendQuirk();
  EXPECT_EQ(GetControlPathContents(true),
            BluetoothControllerTest::kRestoreTestContents);
}

TEST_F(BluetoothControllerTest, RemoveEventHandled) {
  Init();

  SendUdevEvent(system::UdevEvent::Action::ADD, true);
  SendUdevEvent(system::UdevEvent::Action::REMOVE, true);
  controller_->ApplyAutosuspendQuirk();
  EXPECT_EQ(GetControlPathContents(true),
            BluetoothController::kAutosuspendEnabled);
}

TEST_F(BluetoothControllerTest, IgnoreNoControlFile) {
  Init();

  SendUdevEvent(system::UdevEvent::Action::ADD, false);
  EXPECT_EQ(GetControlPathContents(false), kErrorContents);

  controller_->ApplyAutosuspendQuirk();
  EXPECT_EQ(GetControlPathContents(false), kErrorContents);
}

TEST_F(BluetoothControllerTest, UseDeviceFromInit) {
  Init(/*with_existing_valid_device=*/true);

  EXPECT_EQ(GetControlPathContents(true),
            BluetoothController::kAutosuspendEnabled);

  // Disable when applying quirk and enable when unapplying quirk.
  controller_->ApplyAutosuspendQuirk();
  EXPECT_EQ(GetControlPathContents(true),
            BluetoothController::kAutosuspendDisabled);
  controller_->UnapplyAutosuspendQuirk();
  EXPECT_EQ(GetControlPathContents(true),
            BluetoothController::kAutosuspendEnabled);
}

TEST_F(BluetoothControllerTest, TaggedRolesInactiveWithoutFlag) {
  Init(/*with_existing_valid_device=*/false,
       /*with_autosuspend_feature_enabled=*/false);

  // Start with default timeout.
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kDefaultAutosuspendTimeout);

  // Set role and send tagged device info.
  SetPowerdRoleOn("foo", BluetoothController::kBluetoothInputRole);
  SendTaggedDeviceChange("foo");

  // Expect no change.
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kDefaultAutosuspendTimeout);
}

TEST_F(BluetoothControllerTest, TaggedRolesIncreaseAutosuspend) {
  Init(/*with_existing_valid_device=*/false,
       /*with_autosuspend_feature_enabled=*/true);

  // Start with a default timeout.
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kDefaultAutosuspendTimeout);

  // First without any powerd role.
  SendTaggedDeviceChange("foo");
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kDefaultAutosuspendTimeout);

  // Again with the role set.
  SetPowerdRoleOn("foo", BluetoothController::kBluetoothInputRole);
  SetPowerdRoleOn("bar", BluetoothController::kBluetoothInputRole);

  SendTaggedDeviceChange("foo");
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kLongAutosuspendTimeout);
  SendTaggedDeviceRemoved("foo");
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kDefaultAutosuspendTimeout);

  // Try inserting the same device multiple times.
  SendTaggedDeviceChange("foo");
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kLongAutosuspendTimeout);
  SendTaggedDeviceChange("foo");
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kLongAutosuspendTimeout);
  SendTaggedDeviceRemoved("foo");
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kDefaultAutosuspendTimeout);

  // Insert multiple paths pointing to the same path.
  SendTaggedDeviceChange("foo");
  SendTaggedDeviceChange("bar");
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kLongAutosuspendTimeout);
  SendTaggedDeviceRemoved("foo");
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kLongAutosuspendTimeout);
  SendTaggedDeviceRemoved("bar");
  EXPECT_EQ(GetDelayPathContents(),
            BluetoothController::kDefaultAutosuspendTimeout);
}

}  // namespace power_manager::policy
