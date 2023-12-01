// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_INTERFACE_H_
#define LIBBRILLO_BRILLO_USB_USB_INTERFACE_H_

#include <memory>

#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>

struct libusb_interface;

namespace brillo {

class UsbDevice;
class UsbInterfaceDescriptor;

// A USB interface, which wraps a libusb_interface C struct from libusb 1.0 into
// a C++ object.
class BRILLO_EXPORT UsbInterface {
 public:
  // Constructs a UsbInterface object by taking a weak pointer to a UsbDevice
  // object as |device| and a raw pointer to a libusb_interface struct as
  // |interface|. |device| is passed to the constructor of
  // UsbInterfaceDescriptor when creating a UsbInterfaceDescriptor object. The
  // ownership of |interface| is not transferred, and thus it should outlive
  // this object.
  UsbInterface(const base::WeakPtr<UsbDevice>& device,
               const libusb_interface* interface);
  UsbInterface(const UsbInterface&) = delete;
  UsbInterface& operator=(const UsbInterface&) = delete;

  ~UsbInterface() = default;

  // Getters for retrieving fields of the libusb_interface struct.
  int GetNumAlternateSettings() const;

  // Returns a pointer to a UsbInterfaceDescriptor object for the interface
  // descriptor indexed at |index|, or a NULL pointer if the index is invalid.
  // The returned object should not be held beyond the lifetime of this object.
  std::unique_ptr<UsbInterfaceDescriptor> GetAlternateSetting(int index) const;

 private:
  base::WeakPtr<UsbDevice> device_;
  const libusb_interface* const interface_;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_USB_USB_INTERFACE_H_
