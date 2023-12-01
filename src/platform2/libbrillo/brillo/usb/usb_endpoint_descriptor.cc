// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_endpoint_descriptor.h"

#include <libusb.h>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>

namespace brillo {

UsbEndpointDescriptor::UsbEndpointDescriptor(
    const libusb_endpoint_descriptor* endpoint_descriptor)
    : endpoint_descriptor_(endpoint_descriptor) {
  CHECK(endpoint_descriptor_);
}

uint8_t UsbEndpointDescriptor::GetLength() const {
  return endpoint_descriptor_->bLength;
}

uint8_t UsbEndpointDescriptor::GetDescriptorType() const {
  return endpoint_descriptor_->bDescriptorType;
}

uint8_t UsbEndpointDescriptor::GetEndpointAddress() const {
  return endpoint_descriptor_->bEndpointAddress;
}

uint8_t UsbEndpointDescriptor::GetEndpointNumber() const {
  return GetEndpointAddress() & LIBUSB_ENDPOINT_ADDRESS_MASK;
}

uint8_t UsbEndpointDescriptor::GetAttributes() const {
  return endpoint_descriptor_->bmAttributes;
}

uint16_t UsbEndpointDescriptor::GetMaxPacketSize() const {
  return endpoint_descriptor_->wMaxPacketSize;
}

uint8_t UsbEndpointDescriptor::GetInterval() const {
  return endpoint_descriptor_->bInterval;
}

UsbDirection UsbEndpointDescriptor::GetDirection() const {
  uint8_t direction = GetEndpointAddress() & LIBUSB_ENDPOINT_DIR_MASK;
  return (direction == LIBUSB_ENDPOINT_IN) ? kUsbDirectionIn : kUsbDirectionOut;
}

UsbTransferType UsbEndpointDescriptor::GetTransferType() const {
  return static_cast<UsbTransferType>(GetAttributes() &
                                      LIBUSB_TRANSFER_TYPE_MASK);
}

std::string UsbEndpointDescriptor::ToString() const {
  return base::StringPrintf(
      "Endpoint (Length=%u, "
      "DescriptorType=%u, "
      "EndpointAddress=0x%02x, "
      "EndpointNumber=%u, "
      "Attributes=0x%02x, "
      "MaxPacketSize=%u, "
      "Interval=%u, "
      "Direction=%s, "
      "TransferType=%s)",
      GetLength(), GetDescriptorType(), GetEndpointAddress(),
      GetEndpointNumber(), GetAttributes(), GetMaxPacketSize(), GetInterval(),
      UsbDirectionToString(GetDirection()),
      UsbTransferTypeToString(GetTransferType()));
}

}  // namespace brillo

std::ostream& operator<<(
    std::ostream& stream,
    const brillo::UsbEndpointDescriptor& endpoint_descriptor) {
  stream << endpoint_descriptor.ToString();
  return stream;
}
