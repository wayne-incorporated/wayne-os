// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_ENDPOINT_DESCRIPTOR_H_
#define LIBBRILLO_BRILLO_USB_USB_ENDPOINT_DESCRIPTOR_H_

#include <stdint.h>

#include <ostream>  // NOLINT(readability/streams)
#include <string>

#include <brillo/brillo_export.h>

#include "brillo/usb/usb_constants.h"

struct libusb_endpoint_descriptor;

namespace brillo {

// A USB endpoint descriptor, which wraps a libusb_endpoint_descriptor C struct
// from libusb 1.0 into a C++ object.
class BRILLO_EXPORT UsbEndpointDescriptor {
 public:
  // Constructs a UsbEndpointDescriptor object by taking a raw pointer to a
  // libusb_endpoint_descriptor struct as |endpoint_descriptor|. The ownership
  // of |endpoint_descriptor| is not transferred, and thus it should outlive
  // this object.
  explicit UsbEndpointDescriptor(
      const libusb_endpoint_descriptor* endpoint_descriptor);
  UsbEndpointDescriptor(const UsbEndpointDescriptor&) = delete;
  UsbEndpointDescriptor& operator=(const UsbEndpointDescriptor&) = delete;

  ~UsbEndpointDescriptor() = default;

  // Getters for retrieving fields of the libusb_endpoint_descriptor struct.
  uint8_t GetLength() const;
  uint8_t GetDescriptorType() const;
  uint8_t GetEndpointAddress() const;
  uint8_t GetEndpointNumber() const;
  uint8_t GetAttributes() const;
  uint16_t GetMaxPacketSize() const;
  uint8_t GetInterval() const;
  UsbDirection GetDirection() const;
  UsbTransferType GetTransferType() const;

  // Returns a string describing the properties of this object for logging
  // purpose.
  std::string ToString() const;

 private:
  const libusb_endpoint_descriptor* const endpoint_descriptor_;
};

}  // namespace brillo

// Output stream operator provided to facilitate logging.
BRILLO_EXPORT std::ostream& operator<<(
    std::ostream& stream,
    const brillo::UsbEndpointDescriptor& endpoint_descriptor);

#endif  // LIBBRILLO_BRILLO_USB_USB_ENDPOINT_DESCRIPTOR_H_
