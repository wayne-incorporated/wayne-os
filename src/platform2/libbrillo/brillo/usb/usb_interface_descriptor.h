// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_INTERFACE_DESCRIPTOR_H_
#define LIBBRILLO_BRILLO_USB_USB_INTERFACE_DESCRIPTOR_H_

#include <stdint.h>

#include <memory>
#include <ostream>  // NOLINT(readability/streams)
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>

#include "brillo/usb/usb_constants.h"

struct libusb_interface_descriptor;

namespace brillo {

class UsbDevice;
class UsbEndpointDescriptor;

// A USB interface descriptor, which wraps a libusb_interface_descriptor C
// struct from libusb 1.0 into a C++ object.
class BRILLO_EXPORT UsbInterfaceDescriptor {
 public:
  // Constructs a UsbInterfaceDescriptor object by taking a weak pointer to a
  // UsbDevice object as |device| and a raw pointer to a
  // libusb_interface_descriptor struct as |interface_descriptor|. |device| is
  // used for getting USB string descriptors related to this object. The
  // ownership of |interface_descriptor| is not transferred, and thus it should
  // outlive this object.
  UsbInterfaceDescriptor(
      const base::WeakPtr<UsbDevice>& device,
      const libusb_interface_descriptor* interface_descriptor);
  UsbInterfaceDescriptor(const UsbInterfaceDescriptor&) = delete;
  UsbInterfaceDescriptor& operator=(const UsbInterfaceDescriptor&) = delete;

  ~UsbInterfaceDescriptor();

  // Getters for retrieving fields of the libusb_interface_descriptor struct.
  uint8_t GetLength() const;
  uint8_t GetDescriptorType() const;
  uint8_t GetInterfaceNumber() const;
  uint8_t GetAlternateSetting() const;
  uint8_t GetNumEndpoints() const;
  uint8_t GetInterfaceClass() const;
  uint8_t GetInterfaceSubclass() const;
  uint8_t GetInterfaceProtocol() const;
  std::string GetInterfaceDescription() const;

  // Returns a UsbEndpointDescriptor object for the endpoint descriptor indexed
  // at |index|, or a nullptr if |index| is invalid. The returned object should
  // not be held beyond the lifetime of this object.
  std::unique_ptr<UsbEndpointDescriptor> GetEndpointDescriptor(
      uint8_t index) const;

  // Returns a UsbEndpointDescriptor object for the first endpoint descriptor
  // with its transfer type equal to |transfer_type| and its direction equal to
  // |direction|, or a nullptr if not matching endpoint descriptor is found.
  // The returned object should not be held beyond the lifetime of this object.
  std::unique_ptr<UsbEndpointDescriptor>
  GetEndpointDescriptorByTransferTypeAndDirection(UsbTransferType transfer_type,
                                                  UsbDirection direction) const;

  // Returns a string describing the properties of this object for logging
  // purpose.
  std::string ToString() const;

 private:
  base::WeakPtr<UsbDevice> device_;
  const libusb_interface_descriptor* const interface_descriptor_;
};

}  // namespace brillo

// Output stream operator provided to facilitate logging.
BRILLO_EXPORT std::ostream& operator<<(
    std::ostream& stream,
    const brillo::UsbInterfaceDescriptor& interface_descriptor);

#endif  // LIBBRILLO_BRILLO_USB_USB_INTERFACE_DESCRIPTOR_H_
