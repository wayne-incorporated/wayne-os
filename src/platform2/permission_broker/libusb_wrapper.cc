// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/libusb_wrapper.h"

#include <string>
#include <utility>

#include <base/logging.h>
#include <base/time/time.h>

namespace {

constexpr base::TimeDelta kUsbControlTimeout = base::Seconds(5);

const int kLibusbUnrefDevices = 1;

}  // namespace

namespace permission_broker {

UsbDevice::UsbDevice(libusb_device* device)
    : device_(device, libusb_unref_device) {
  // Increase the ref count to gain ownership of the libusb device object.
  libusb_ref_device(device_.get());

  // Try to obtain information regarding the device VID/PID from the device
  // itself.
  // NB: in the repositories we only depend on versions of libusb which are
  //     newer than 1.0.16. This means that we can ignore the return value
  //     as this API always suceeds in such a case.
  libusb_device_descriptor descriptor;
  libusb_get_device_descriptor(device_.get(), &descriptor);
  info_.vid = descriptor.idVendor;
  info_.pid = descriptor.idProduct;
  info_.device_class = descriptor.bDeviceClass;
}

UsbDevice::~UsbDevice() = default;

UsbDeviceInfo UsbDevice::GetInfo() const {
  return info_;
}

std::unique_ptr<UsbDeviceInterface> UsbDevice::GetParent() const {
  libusb_device* parent_device = libusb_get_parent(device_.get());
  if (parent_device == nullptr) {
    LOG(ERROR) << "Unable to find the device parent for '" << info_ << "'";
    return nullptr;
  }
  auto parent =
      std::unique_ptr<UsbDeviceInterface>(new UsbDevice(parent_device));

  UsbDeviceInfo parent_info = parent->GetInfo();
  if (parent_info.device_class != LIBUSB_CLASS_HUB) {
    LOG(ERROR) << "The parent device found for this USB device is not a hub ("
               << parent_info << ")";
    return nullptr;
  }

  return parent;
}

uint8_t UsbDevice::GetPort() const {
  return libusb_get_port_number(device_.get());
}

bool UsbDevice::SetPowerState(bool enabled, uint16_t port) const {
  if (info_.device_class != LIBUSB_CLASS_HUB) {
    LOG(ERROR) << "Unable to set power on a port if the device is not a hub "
               << "(device '" << info_ << "')";
    return false;
  }

  libusb_device_handle* handle;
  int result = libusb_open(device_.get(), &handle);
  if (result != LIBUSB_SUCCESS) {
    LOG(ERROR) << "Unable to open the USB device. (error: "
               << libusb_error_name(result) << ")";
    return false;
  }

  uint8_t request =
      enabled ? LIBUSB_REQUEST_SET_FEATURE : LIBUSB_REQUEST_CLEAR_FEATURE;
  result = libusb_control_transfer(
      handle,
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-enum-enum-conversion"
      LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_OTHER,
#pragma clang diagnostic pop
      request, USB_PORT_FEAT_POWER, port, nullptr, 0,
      kUsbControlTimeout.InMilliseconds());
  libusb_close(handle);

  if (result < 0) {
    std::string status = enabled ? "on" : "off";
    LOG(WARNING) << "Unable to power " << status << " device '" << info_
                 << "' (error: " << libusb_error_name(result) << ")";
    return false;
  }

  return true;
}

UsbDeviceManager::UsbDeviceManager() {
  libusb_context* ctx;
  int status = libusb_init(&ctx);
  if (status != LIBUSB_SUCCESS) {
    LOG(ERROR) << "Unable to initialize the libusb context. (error: "
               << libusb_error_name(status) << ")";
    return;
  }
  context_.reset(ctx);
}

UsbDeviceManager::~UsbDeviceManager() = default;

std::vector<std::unique_ptr<UsbDeviceInterface>>
UsbDeviceManager::GetDevicesByVidPid(uint16_t vid, uint16_t pid) {
  libusb_device** device_list;
  std::vector<std::unique_ptr<UsbDeviceInterface>> devices;

  int num_of_devices = libusb_get_device_list(context_.get(), &device_list);
  if (num_of_devices < 0) {
    LOG(ERROR) << "Unable to access the libusb device list. (error: "
               << libusb_error_name(num_of_devices) << ")";
    return devices;
  }

  for (int i = 0; i < num_of_devices; ++i) {
    auto device = std::make_unique<UsbDevice>(device_list[i]);
    UsbDeviceInfo info = device->GetInfo();

    if (info.vid == vid && info.pid == pid) {
      devices.push_back(std::move(device));
    }
  }

  // Free the list of devices previously retrieved.
  libusb_free_device_list(device_list, kLibusbUnrefDevices);
  return devices;
}

}  // namespace permission_broker
