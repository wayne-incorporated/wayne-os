// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "rmad/udev/udev_utils.h"

#include <utility>

#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>
#include <brillo/udev/udev_enumerate.h>

#include "rmad/udev/udev_device.h"

namespace rmad {

UdevUtilsImpl::UdevUtilsImpl() : udev_(brillo::Udev::Create()) {}

UdevUtilsImpl::UdevUtilsImpl(std::unique_ptr<brillo::Udev> udev)
    : udev_(std::move(udev)) {}

UdevUtilsImpl::~UdevUtilsImpl() = default;

std::vector<std::unique_ptr<UdevDevice>>
UdevUtilsImpl::EnumerateBlockDevices() {
  std::unique_ptr<brillo::UdevEnumerate> enumerate = udev_->CreateEnumerate();
  enumerate->AddMatchSubsystem("block");
  enumerate->ScanDevices();

  std::vector<std::unique_ptr<UdevDevice>> devices;
  for (std::unique_ptr<brillo::UdevListEntry> entry = enumerate->GetListEntry();
       entry; entry = entry->GetNext()) {
    std::unique_ptr<brillo::UdevDevice> dev =
        udev_->CreateDeviceFromSysPath(entry->GetName());
    if (dev) {
      devices.emplace_back(std::make_unique<UdevDeviceImpl>(std::move(dev)));
    }
  }
  return devices;
}

bool UdevUtilsImpl::GetBlockDeviceFromDevicePath(
    const std::string& device_path, std::unique_ptr<UdevDevice>* dev) {
  std::vector<std::unique_ptr<UdevDevice>> devices = EnumerateBlockDevices();
  for (auto& device : devices) {
    if (device->GetDeviceNode() == device_path) {
      *dev = std::move(device);
      return true;
    }
  }
  return false;
}

}  // namespace rmad
