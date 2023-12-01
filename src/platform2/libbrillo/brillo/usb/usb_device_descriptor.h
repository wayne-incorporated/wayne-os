// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_DEVICE_DESCRIPTOR_H_
#define LIBBRILLO_BRILLO_USB_USB_DEVICE_DESCRIPTOR_H_

#include <stdint.h>

#include <ostream>  // NOLINT(readability/streams)
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>

struct libusb_device_descriptor;

namespace brillo {

class UsbDevice;

// A USB device descriptor, which wraps a libusb_device_descriptor C struct from
// libusb 1.0 into a C++ object.
class BRILLO_EXPORT UsbDeviceDescriptor {
 public:
  // Constructs a UsbDeviceDescriptor object by taking a weak pointer to a
  // UsbDevice object as |device| and a raw pointer to a
  // libusb_device_descriptor struct as |device_descriptor|. |device| is
  // used for getting USB string descriptors related to this object. The
  // ownership of |device_descriptor| is not transferred, and thus it should
  // outlive this object.
  UsbDeviceDescriptor(const base::WeakPtr<UsbDevice>& device,
                      const libusb_device_descriptor* device_descriptor);
  UsbDeviceDescriptor(const UsbDeviceDescriptor&) = delete;
  UsbDeviceDescriptor& operator=(const UsbDeviceDescriptor&) = delete;

  ~UsbDeviceDescriptor() = default;

  // Getters for retrieving fields of the libusb_device_descriptor struct.
  uint8_t GetLength() const;
  uint8_t GetDescriptorType() const;
  uint8_t GetDeviceClass() const;
  uint8_t GetDeviceSubclass() const;
  uint8_t GetDeviceProtocol() const;
  uint8_t GetMaxPacketSize0() const;
  uint16_t GetVendorId() const;
  uint16_t GetProductId() const;
  std::string GetManufacturer() const;
  std::string GetProduct() const;
  std::string GetSerialNumber() const;
  uint8_t GetNumConfigurations() const;

  // Returns a string describing the properties of this object for logging
  // purpose.
  std::string ToString() const;

 private:
  base::WeakPtr<UsbDevice> device_;
  const libusb_device_descriptor* const device_descriptor_;
};

}  // namespace brillo

// Output stream operator provided to facilitate logging.
BRILLO_EXPORT std::ostream& operator<<(
    std::ostream& stream, const brillo::UsbDeviceDescriptor& device_descriptor);

#endif  // LIBBRILLO_BRILLO_USB_USB_DEVICE_DESCRIPTOR_H_
