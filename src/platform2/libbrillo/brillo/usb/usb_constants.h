// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_CONSTANTS_H_
#define LIBBRILLO_BRILLO_USB_USB_CONSTANTS_H_

#include <stdint.h>

#include <ostream>  // NOLINT(readability/streams)

#include <brillo/brillo_export.h>

namespace brillo {

// USB class codes.
enum UsbClass { kUsbClassCommunication = 0x02, kUsbClassMassStorage = 0x08 };

// USB subclass codes.
enum UsbSubClass { kUsbSubClassMBIM = 0x0e };

// USB endpoint direction, which is one-to-one equivalent to the
// libusb_endpoint_direction enum defined in libusb 1.0.
enum UsbDirection {
  // Device to host.
  kUsbDirectionIn = 0x80,
  // Host to device.
  kUsbDirectionOut = 0x00
};

// USB speed codes, which is one-to-one equivalent to the libusb_speed enum
// defined in libusb 1.0.
enum UsbSpeed {
  kUsbSpeedUnknown = 0,
  kUsbSpeedLow = 1,
  kUsbSpeedFull = 2,
  kUsbSpeedHigh = 3,
  kUsbSpeedSuper = 4
};

// USB endpoint transfer type, which is one-to-one equivalent to the
// libusb_transfer_type enum defined in libusb 1.0.
enum UsbTransferType {
  kUsbTransferTypeControl = 0,
  kUsbTransferTypeIsochronous = 1,
  kUsbTransferTypeBulk = 2,
  kUsbTransferTypeInterrupt = 3,
  // Additional enum value to indicate an uninitialized/unknown transfer type.
  kUsbTransferTypeUnknown = -1
};

// USB endpoint transfer status, which is one-to-one equivalent to the
// libusb_transfer_status enum defined in libusb 1.0.
enum UsbTransferStatus {
  kUsbTransferStatusCompleted,
  kUsbTransferStatusError,
  kUsbTransferStatusTimedOut,
  kUsbTransferStatusCancelled,
  kUsbTransferStatusStall,
  kUsbTransferStatusNoDevice,
  kUsbTransferStatusOverflow,
  // Additional enum value to indicate an unknown transfer status.
  kUsbTransferStatusUnknown
};

// Invalid USB configuration value
const int kUsbConfigurationValueInvalid = -1;

// Returns the USB endpoint direction of |endpoint_address|.
BRILLO_EXPORT UsbDirection
GetUsbDirectionOfEndpointAddress(uint8_t endpoint_address);

// Returns a string describing the USB endpoint direction |direction|.
BRILLO_EXPORT const char* UsbDirectionToString(UsbDirection direction);

// Returns a string describing the USB speed code |speed|.
BRILLO_EXPORT const char* UsbSpeedToString(UsbSpeed speed);

// Returns a string describing the USB endpoint transfer type |transfer_type|.
BRILLO_EXPORT const char* UsbTransferTypeToString(
    UsbTransferType transfer_type);

// Returns a string describing the USB endpoint transfer status
// |transfer_status|.
BRILLO_EXPORT const char* UsbTransferStatusToString(
    UsbTransferStatus transfer_status);

}  // namespace brillo

// Output stream operators provided to facilitate logging.
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       brillo::UsbDirection direction);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       brillo::UsbSpeed speed);
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       brillo::UsbTransferType transfer_type);
BRILLO_EXPORT std::ostream& operator<<(
    std::ostream& stream, brillo::UsbTransferStatus transfer_status);

#endif  // LIBBRILLO_BRILLO_USB_USB_CONSTANTS_H_
