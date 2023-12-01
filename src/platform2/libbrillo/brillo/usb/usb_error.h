// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_ERROR_H_
#define LIBBRILLO_BRILLO_USB_USB_ERROR_H_

#include <ostream>  // NOLINT(readability/streams)

#include <libusb.h>

#include <brillo/brillo_export.h>

namespace brillo {

// A USB error, which represents one of the errors defined by libusb 1.0 in the
// libusb_error enum and some additional errors defined by mist.
class BRILLO_EXPORT UsbError {
 public:
  enum Type {
    // Errors that correspond to those in the libusb_error enum defined by
    // libusb.
    kSuccess,
    kErrorIO,
    kErrorInvalidParameter,
    kErrorAccess,
    kErrorNoDevice,
    kErrorNotFound,
    kErrorBusy,
    kErrorTimeout,
    kErrorOverflow,
    kErrorPipe,
    kErrorInterrupted,
    kErrorNoMemory,
    kErrorNotSupported,
    kErrorOther,

    // Additional errors.
    kErrorDeviceNotOpen,
    kErrorTransferAlreadyAllocated,
    kErrorTransferNotAllocated,
    kErrorTransferAlreadySubmitted,
    kErrorTransferNotSubmitted,
    kErrorTransferBeingCancelled
  };

  // Constructs a UsbError object with its error type set to UsbError::kSuccess.
  UsbError();

  // Constructs a UsbError object with its error type set to |type|.
  explicit UsbError(Type type);

  // Constructs a UsbError object with its error type set to a value equivalent
  // to the libusb error |error|.
  explicit UsbError(libusb_error error);
  UsbError(const UsbError&) = delete;
  UsbError& operator=(const UsbError&) = delete;

  ~UsbError() = default;

  // Returns true if the error type of this object is set to UsbError::kSuccess,
  // or false otherwise.
  bool IsSuccess() const;

  // Returns a string describing the error type of this object for logging
  // purpose.
  const char* ToString() const;

  // Resets the error type of this object to UsbError::kSuccess.
  void Clear();

  // Sets the error type of this object to a value equivalent to the libusb
  // error |error|. Returns true if the error type of this object is set to
  // UsbError::kSuccess, or false otherwise.
  bool SetFromLibUsbError(libusb_error error);

  Type type() const { return type_; }
  void set_type(Type type) { type_ = type; }

 private:
  Type type_;
};

}  // namespace brillo

// Output stream operator provided to facilitate logging.
BRILLO_EXPORT std::ostream& operator<<(std::ostream& stream,
                                       const brillo::UsbError& error);

#endif  // LIBBRILLO_BRILLO_USB_USB_ERROR_H_
