// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "lorgnette/usb/libusb_wrapper_impl.h"

#include <base/logging.h>

#include "lorgnette/usb/usb_device_impl.h"

namespace lorgnette {

std::unique_ptr<LibusbWrapperImpl> LibusbWrapperImpl::Create() {
  libusb_context* context;
  if (libusb_init(&context) != 0) {
    LOG(ERROR) << "Error initializing libusb";
    return nullptr;
  }

  return std::unique_ptr<LibusbWrapperImpl>(new LibusbWrapperImpl(context));
}

LibusbWrapperImpl::LibusbWrapperImpl(libusb_context* context)
    : context_(context) {}

LibusbWrapperImpl::~LibusbWrapperImpl() {
  libusb_exit(context_);
}

std::vector<std::unique_ptr<UsbDevice>> LibusbWrapperImpl::GetDevices() {
  libusb_device** dev_list;
  ssize_t num_devices = libusb_get_device_list(context_, &dev_list);
  if (num_devices < 0) {
    LOG(ERROR) << "Failed to enumerate USB devices: "
               << libusb_error_name(num_devices);
    return {};
  }

  std::vector<std::unique_ptr<UsbDevice>> devices;
  for (ssize_t i = 0; i < num_devices; i++) {
    devices.emplace_back(UsbDeviceImpl::Create(dev_list[i]));
  }

  libusb_free_device_list(dev_list, 1);
  return devices;
}

}  // namespace lorgnette
