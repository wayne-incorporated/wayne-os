// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_device_descriptor.h"

#include <libusb.h>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "brillo/usb/usb_device.h"

namespace brillo {

UsbDeviceDescriptor::UsbDeviceDescriptor(
    const base::WeakPtr<UsbDevice>& device,
    const libusb_device_descriptor* device_descriptor)
    : device_(device), device_descriptor_(device_descriptor) {
  CHECK(device_descriptor_);
}

uint8_t UsbDeviceDescriptor::GetLength() const {
  return device_descriptor_->bLength;
}

uint8_t UsbDeviceDescriptor::GetDescriptorType() const {
  return device_descriptor_->bDescriptorType;
}

uint8_t UsbDeviceDescriptor::GetDeviceClass() const {
  return device_descriptor_->bDeviceClass;
}

uint8_t UsbDeviceDescriptor::GetDeviceSubclass() const {
  return device_descriptor_->bDeviceSubClass;
}

uint8_t UsbDeviceDescriptor::GetDeviceProtocol() const {
  return device_descriptor_->bDeviceProtocol;
}

uint8_t UsbDeviceDescriptor::GetMaxPacketSize0() const {
  return device_descriptor_->bMaxPacketSize0;
}

uint16_t UsbDeviceDescriptor::GetVendorId() const {
  return device_descriptor_->idVendor;
}

uint16_t UsbDeviceDescriptor::GetProductId() const {
  return device_descriptor_->idProduct;
}

std::string UsbDeviceDescriptor::GetManufacturer() const {
  return device_ ? device_->GetStringDescriptorAscii(
                       device_descriptor_->iManufacturer)
                 : std::string();
}

std::string UsbDeviceDescriptor::GetProduct() const {
  return device_
             ? device_->GetStringDescriptorAscii(device_descriptor_->iProduct)
             : std::string();
}

std::string UsbDeviceDescriptor::GetSerialNumber() const {
  return device_ ? device_->GetStringDescriptorAscii(
                       device_descriptor_->iSerialNumber)
                 : std::string();
}

uint8_t UsbDeviceDescriptor::GetNumConfigurations() const {
  return device_descriptor_->bNumConfigurations;
}

std::string UsbDeviceDescriptor::ToString() const {
  return base::StringPrintf(
      "Device (Length=%u, "
      "DescriptorType=%u, "
      "DeviceClass=%u, "
      "DeviceSubclass=%u, "
      "DeviceProtocol=%u, "
      "MaxPacketSize0=%u, "
      "VendorId=0x%04x, "
      "ProductId=0x%04x, "
      "Manufacturer='%s', "
      "Product='%s', "
      "SerialNumber='%s', "
      "NumConfigurations=%d)",
      GetLength(), GetDescriptorType(), GetDeviceClass(), GetDeviceSubclass(),
      GetDeviceProtocol(), GetMaxPacketSize0(), GetVendorId(), GetProductId(),
      GetManufacturer().c_str(), GetProduct().c_str(),
      GetSerialNumber().c_str(), GetNumConfigurations());
}

}  // namespace brillo

std::ostream& operator<<(std::ostream& stream,
                         const brillo::UsbDeviceDescriptor& device_descriptor) {
  stream << device_descriptor.ToString();
  return stream;
}
