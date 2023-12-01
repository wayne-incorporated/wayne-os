// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_USB_USB_DEVICE_IMPL_H_
#define LORGNETTE_USB_USB_DEVICE_IMPL_H_

#include <memory>
#include <string>
#include <vector>

#include <libusb.h>

#include "lorgnette/usb/usb_device.h"

namespace lorgnette {

class UsbDeviceImpl : public UsbDevice {
 public:
  ~UsbDeviceImpl() override = default;

  static std::unique_ptr<UsbDeviceImpl> Create(libusb_device* device);

  std::optional<libusb_device_descriptor> GetDeviceDescriptor() const override;
  ScopedConfigDescriptor GetConfigDescriptor(uint8_t config) const override;
  std::optional<std::string> GetStringDescriptor(uint8_t index) override;

 private:
  explicit UsbDeviceImpl(libusb_device* device);
  libusb_device* device_;
};

}  // namespace lorgnette

#endif  // LORGNETTE_USB_USB_DEVICE_IMPL_H_
