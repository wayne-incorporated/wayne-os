// Copyright 2017 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/pluggable_internal_backlight.h"

#include <string>

#include <base/check.h>
#include <base/check_op.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gtest/gtest.h>

#include "power_manager/common/power_constants.h"
#include "power_manager/common/util.h"
#include "power_manager/powerd/system/backlight_observer.h"
#include "power_manager/powerd/system/internal_backlight.h"
#include "power_manager/powerd/system/udev_stub.h"
#include "power_manager/powerd/testing/test_environment.h"

namespace power_manager::system {

namespace {

const char* const kSubsystem = kKeyboardBacklightUdevSubsystem;

constexpr char kSuffix[] = ":kbd_backlight";
constexpr char kPattern[] = "*:kbd_backlight";

// BacklightObserver implementation for testing that just counts changes.
class TestObserver : public BacklightObserver {
 public:
  explicit TestObserver(BacklightInterface* backlight) : backlight_(backlight) {
    backlight_->AddObserver(this);
  }
  TestObserver(const TestObserver&) = delete;
  TestObserver& operator=(const TestObserver&) = delete;

  ~TestObserver() override { backlight_->RemoveObserver(this); }

  int num_changes() const { return num_changes_; }

  // BacklightObserver:
  void OnBacklightDeviceChanged(BacklightInterface* backlight) override {
    DCHECK_EQ(backlight, backlight_);
    num_changes_++;
  }

 private:
  BacklightInterface* backlight_;  // Not owned.

  // Number of times that OnBacklightDeviceChanged() has been called.
  int num_changes_ = 0;
};

}  // namespace

class PluggableInternalBacklightTest : public TestEnvironment {
 public:
  PluggableInternalBacklightTest() {
    CHECK(temp_dir_.CreateUniqueTempDir());
    backlight_.Init(&udev_, kSubsystem, temp_dir_.GetPath(), kPattern);
  }
  PluggableInternalBacklightTest(const PluggableInternalBacklightTest&) =
      delete;
  PluggableInternalBacklightTest& operator=(
      const PluggableInternalBacklightTest&) = delete;

  ~PluggableInternalBacklightTest() override = default;

 protected:
  // Creates a directory for a device named |device_name| under |temp_dir_| and
  // fills it with files describing current brightness |brightness| and maximum
  // brightness |max_brightness|. The directory is returned.
  base::FilePath CreateBacklightDir(const std::string& device_name,
                                    int64_t brightness,
                                    int64_t max_brightness) {
    const base::FilePath path = temp_dir_.GetPath().Append(device_name);
    CHECK(base::CreateDirectory(path));
    CHECK(util::WriteInt64File(
        path.Append(InternalBacklight::kBrightnessFilename), brightness));
    CHECK(util::WriteInt64File(
        path.Append(InternalBacklight::kMaxBrightnessFilename),
        max_brightness));
    return path;
  }

  base::ScopedTempDir temp_dir_;
  UdevStub udev_;
  PluggableInternalBacklight backlight_;
};

TEST_F(PluggableInternalBacklightTest, NoDevice) {
  // Everything should fail if the underlying device is missing.
  EXPECT_FALSE(backlight_.DeviceExists());
  EXPECT_EQ(-1, backlight_.GetMaxBrightnessLevel());
  EXPECT_EQ(-1, backlight_.GetCurrentBrightnessLevel());
  EXPECT_FALSE(backlight_.SetBrightnessLevel(128, base::TimeDelta()));
  EXPECT_FALSE(backlight_.TransitionInProgress());
}

TEST_F(PluggableInternalBacklightTest, ChangeDevice) {
  TestObserver observer(&backlight_);
  EXPECT_FALSE(backlight_.DeviceExists());
  EXPECT_TRUE(udev_.HasSubsystemObserver(kSubsystem, &backlight_));

  // Add a device and announce it over udev.
  const auto kDevice = std::string("device") + kSuffix;
  constexpr int64_t kBrightness = 128;
  constexpr int64_t kMaxBrightness = 255;
  base::FilePath dir = CreateBacklightDir(kDevice, kBrightness, kMaxBrightness);
  udev_.NotifySubsystemObservers(
      {{kSubsystem, "", kDevice, ""}, UdevEvent::Action::ADD});
  EXPECT_TRUE(backlight_.DeviceExists());
  EXPECT_EQ(kBrightness, backlight_.GetCurrentBrightnessLevel());
  EXPECT_EQ(kMaxBrightness, backlight_.GetMaxBrightnessLevel());
  EXPECT_EQ(1, observer.num_changes());

  // Remove the device.
  ASSERT_TRUE(base::DeletePathRecursively(dir));
  udev_.NotifySubsystemObservers(
      {{kSubsystem, "", kDevice, ""}, UdevEvent::Action::REMOVE});
  EXPECT_FALSE(backlight_.DeviceExists());
  EXPECT_EQ(2, observer.num_changes());

  // Add a different device.
  const auto kDevice2 = std::string("device2") + kSuffix;
  constexpr int64_t kBrightness2 = 50;
  constexpr int64_t kMaxBrightness2 = 100;
  CreateBacklightDir(kDevice2, kBrightness2, kMaxBrightness2);
  udev_.NotifySubsystemObservers(
      {{kSubsystem, "", kDevice2, ""}, UdevEvent::Action::ADD});
  EXPECT_TRUE(backlight_.DeviceExists());
  EXPECT_EQ(kBrightness2, backlight_.GetCurrentBrightnessLevel());
  EXPECT_EQ(kMaxBrightness2, backlight_.GetMaxBrightnessLevel());
  EXPECT_EQ(3, observer.num_changes());
}

TEST_F(PluggableInternalBacklightTest, InvalidDevice) {
  EXPECT_TRUE(udev_.HasSubsystemObserver(kSubsystem, &backlight_));
  TestObserver observer(&backlight_);

  // When a device's name isn't matched by the pattern, it should be ignored.
  constexpr char kDevice[] = "bogus_device";
  CreateBacklightDir(kDevice, 127, 255);
  udev_.NotifySubsystemObservers(
      {{kSubsystem, "", kDevice, ""}, UdevEvent::Action::ADD});
  EXPECT_FALSE(backlight_.DeviceExists());
  EXPECT_EQ(0, observer.num_changes());
}

}  // namespace power_manager::system
