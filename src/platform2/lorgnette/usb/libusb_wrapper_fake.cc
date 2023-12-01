// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/usb/libusb_wrapper_fake.h"

#include <cstdint>
#include <utility>

#include "lorgnette/usb/usb_device.h"
#include "lorgnette/usb/usb_device_fake.h"

namespace lorgnette {

std::vector<std::unique_ptr<UsbDevice>> LibusbWrapperFake::GetDevices() {
  std::vector<std::unique_ptr<UsbDevice>> devices;
  for (auto& d : devices_) {
    devices.emplace_back(UsbDeviceFake::Clone(*d.get()));
  }
  return devices;
}

void LibusbWrapperFake::SetDevices(
    std::vector<std::unique_ptr<UsbDevice>> devices) {
  devices_ = std::move(devices);
}

}  // namespace lorgnette
