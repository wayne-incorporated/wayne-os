// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_interface_descriptor.h"

#include <libusb.h>

#include <memory>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

#include "brillo/usb/usb_device.h"
#include "brillo/usb/usb_endpoint_descriptor.h"

namespace brillo {

UsbInterfaceDescriptor::UsbInterfaceDescriptor(
    const base::WeakPtr<UsbDevice>& device,
    const libusb_interface_descriptor* interface_descriptor)
    : device_(device), interface_descriptor_(interface_descriptor) {
  CHECK(interface_descriptor_);
}

UsbInterfaceDescriptor::~UsbInterfaceDescriptor() {}

uint8_t UsbInterfaceDescriptor::GetLength() const {
  return interface_descriptor_->bLength;
}

uint8_t UsbInterfaceDescriptor::GetDescriptorType() const {
  return interface_descriptor_->bDescriptorType;
}

uint8_t UsbInterfaceDescriptor::GetInterfaceNumber() const {
  return interface_descriptor_->bInterfaceNumber;
}

uint8_t UsbInterfaceDescriptor::GetAlternateSetting() const {
  return interface_descriptor_->bAlternateSetting;
}

uint8_t UsbInterfaceDescriptor::GetNumEndpoints() const {
  return interface_descriptor_->bNumEndpoints;
}

uint8_t UsbInterfaceDescriptor::GetInterfaceClass() const {
  return interface_descriptor_->bInterfaceClass;
}

uint8_t UsbInterfaceDescriptor::GetInterfaceSubclass() const {
  return interface_descriptor_->bInterfaceSubClass;
}

uint8_t UsbInterfaceDescriptor::GetInterfaceProtocol() const {
  return interface_descriptor_->bInterfaceProtocol;
}

std::string UsbInterfaceDescriptor::GetInterfaceDescription() const {
  return device_ ? device_->GetStringDescriptorAscii(
                       interface_descriptor_->iInterface)
                 : std::string();
}

std::unique_ptr<UsbEndpointDescriptor>
UsbInterfaceDescriptor::GetEndpointDescriptor(uint8_t index) const {
  if (index >= GetNumEndpoints()) {
    LOG(ERROR) << base::StringPrintf(
        "Invalid endpoint index %d. Must be less than %d.", index,
        GetNumEndpoints());
    return nullptr;
  }

  return std::make_unique<UsbEndpointDescriptor>(
      &interface_descriptor_->endpoint[index]);
}

std::unique_ptr<UsbEndpointDescriptor>
UsbInterfaceDescriptor::GetEndpointDescriptorByTransferTypeAndDirection(
    UsbTransferType transfer_type, UsbDirection direction) const {
  for (uint8_t i = 0; i < GetNumEndpoints(); ++i) {
    std::unique_ptr<UsbEndpointDescriptor> endpoint_descriptor =
        GetEndpointDescriptor(i);
    if ((endpoint_descriptor->GetTransferType() == transfer_type) &&
        (endpoint_descriptor->GetDirection() == direction)) {
      return endpoint_descriptor;
    }
  }
  return nullptr;
}

std::string UsbInterfaceDescriptor::ToString() const {
  return base::StringPrintf(
      "Interface (Length=%u, "
      "DescriptorType=%u, "
      "InterfaceNumber=%u, "
      "AlternateSetting=%u, "
      "NumEndpoints=%u, "
      "InterfaceClass=%u, "
      "InterfaceSubclass=%u, "
      "InterfaceProtocol=%u, "
      "Interface='%s')",
      GetLength(), GetDescriptorType(), GetInterfaceNumber(),
      GetAlternateSetting(), GetNumEndpoints(), GetInterfaceClass(),
      GetInterfaceSubclass(), GetInterfaceProtocol(),
      GetInterfaceDescription().c_str());
}

}  // namespace brillo

std::ostream& operator<<(
    std::ostream& stream,
    const brillo::UsbInterfaceDescriptor& interface_descriptor) {
  stream << interface_descriptor.ToString();
  return stream;
}
