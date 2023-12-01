// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "power_manager/powerd/system/usb_backlight.h"

#include <cmath>
#include <fcntl.h>
#include <string>
#include <utility>

#include <base/check.h>
#include <base/files/scoped_file.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <libec/ec_command.h>
#include <libec/ec_usb_endpoint.h>
#include <libec/pwm_command.h>
#include <libec/rgb_keyboard_command.h>

#include "power_manager/powerd/system/backlight_observer.h"
#include "power_manager/powerd/system/tagged_device.h"
#include "power_manager/powerd/system/udev.h"
#include "power_manager/powerd/system/udev_tagged_device_observer.h"

namespace power_manager::system {

constexpr int kMaxBrightnessLevel = 100;
constexpr char kUsbRgbBacklightRole[] = "role_usb_rgb_backlight";

UsbBacklight::UsbBacklight(UdevInterface* udev) : udev_(udev) {
  if (udev_)
    udev_->AddTaggedDeviceObserver(this);
}

void UsbBacklight::AddObserver(BacklightObserver* observer) {
  DCHECK(observer);
  observers_.AddObserver(observer);
}

void UsbBacklight::RemoveObserver(BacklightObserver* observer) {
  DCHECK(observer);
  observers_.RemoveObserver(observer);
}

void UsbBacklight::ReleaseDevice() {
  usb_endpoint_.reset();
  max_brightness_level_ = -1;
  current_brightness_level_ = -1;
}

bool UsbBacklight::UpdateDevice() {
  usb_endpoint_ = std::make_unique<ec::EcUsbEndpoint>();
  // TODO(b/265492733): Move to EcCommandFactory to allow mocking for unittests.
  auto get_cmd = std::make_unique<ec::GetKeyboardBacklightCommand>();

  if (!usb_endpoint_->Init(ec::kUsbVidGoogle, ec::kUsbPidCrosEc)) {
    LOG(ERROR) << "Failed to initialize USB backlight. "
               << "This is expected on system startup or after FW update.";
    ReleaseDevice();
    return false;
  }

  if (!get_cmd->Run(*usb_endpoint_)) {
    LOG(ERROR) << "Failed to read backlight brightness over USB";
    ReleaseDevice();
    return false;
  }

  LOG(INFO) << "Initialized USB backlight";
  max_brightness_level_ = kMaxBrightnessLevel;
  current_brightness_level_ = get_cmd->Brightness();

  for (BacklightObserver& observer : observers_)
    observer.OnBacklightDeviceChanged(this);

  return true;
}

bool UsbBacklight::DeviceExists() const {
  return usb_endpoint_ != nullptr;
}

bool UsbBacklight::SetBrightnessLevel(int64_t level, base::TimeDelta interval) {
  return DeviceExists() ? DoSetBrightnessLevel(level, interval) : false;
}

bool UsbBacklight::WriteBrightness(int64_t new_level) {
  if (!DeviceExists())
    return false;

  ec::SetKeyboardBacklightCommand cmd(new_level);
  if (!cmd.Run(*usb_endpoint_)) {
    LOG(INFO) << "Failed to set backlight brightness";
    return false;
  }

  current_brightness_level_ = new_level;
  return true;
}

void UsbBacklight::OnTaggedDeviceChanged(const system::TaggedDevice& device) {
  if (device.HasTag(kUsbRgbBacklightRole)) {
    LOG(INFO) << "Got a change event for device with tag "
              << kUsbRgbBacklightRole;
    // No need to recreate endpoint on every change event.
    if (!DeviceExists())
      UpdateDevice();
  }
}

void UsbBacklight::OnTaggedDeviceRemoved(const system::TaggedDevice& device) {
  if (device.HasTag(kUsbRgbBacklightRole)) {
    LOG(INFO) << "Got a remove event for device with tag "
              << kUsbRgbBacklightRole;
    ReleaseDevice();
  }
}

}  // namespace power_manager::system
