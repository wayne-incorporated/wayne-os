// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_CONFIG_DESCRIPTOR_H_
#define LIBBRILLO_BRILLO_USB_USB_CONFIG_DESCRIPTOR_H_

#include <stdint.h>

#include <memory>
#include <ostream>  // NOLINT(readability/streams)
#include <string>

#include <base/memory/weak_ptr.h>
#include <brillo/brillo_export.h>
#include <gtest/gtest_prod.h>

struct libusb_config_descriptor;

namespace brillo {

class UsbDevice;
class UsbInterface;

// A USB configuration descriptor, which wraps a libusb_config_descriptor C
// struct from libusb 1.0 into a C++ object.
class BRILLO_EXPORT UsbConfigDescriptor {
 public:
  // Constructs a UsbConfigDescriptor object by taking a weak pointer to a
  // UsbDevice object as |device| and a raw pointer to a
  // libusb_config_descriptor struct as |config_descriptor|. |device| is
  // used for getting USB string descriptors related to this object. The
  // ownership of |config_descriptor| is transferred to this object if
  // |own_config_descriptor| is true. Otherwise, |config_descriptor| should
  // outlive this object.
  UsbConfigDescriptor(const base::WeakPtr<UsbDevice>& device,
                      libusb_config_descriptor* config_descriptor,
                      bool own_config_descriptor);
  UsbConfigDescriptor(const UsbConfigDescriptor&) = delete;
  UsbConfigDescriptor& operator=(const UsbConfigDescriptor&) = delete;

  // Destructs this UsbConfigDescriptor object and frees the underlying
  // libusb_config_descriptor struct if that is owned by this object.
  ~UsbConfigDescriptor();

  // Getters for retrieving fields of the libusb_config_descriptor struct.
  uint8_t GetLength() const;
  uint8_t GetDescriptorType() const;
  uint16_t GetTotalLength() const;
  uint8_t GetNumInterfaces() const;
  uint8_t GetConfigurationValue() const;
  std::string GetConfigurationDescription() const;
  uint8_t GetAttributes() const;
  uint8_t GetMaxPower() const;

  // Returns an UsbInterface object for the USB interface indexed at |index|,
  // or a nullptr if the index is invalid. The returned object should not be
  // held beyond the lifetime of this object.
  std::unique_ptr<UsbInterface> GetInterface(uint8_t index) const;

  // Returns a string describing the properties of this object for logging
  // purpose.
  std::string ToString() const;

 private:
  FRIEND_TEST(UsbConfigDescriptorTest, TrivialGetters);

  base::WeakPtr<UsbDevice> device_;
  libusb_config_descriptor* config_descriptor_;
  bool own_config_descriptor_;
};

}  // namespace brillo

// Output stream operator provided to facilitate logging.
BRILLO_EXPORT std::ostream& operator<<(
    std::ostream& stream, const brillo::UsbConfigDescriptor& config_descriptor);

#endif  // LIBBRILLO_BRILLO_USB_USB_CONFIG_DESCRIPTOR_H_
