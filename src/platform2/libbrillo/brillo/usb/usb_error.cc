// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_error.h"

namespace brillo {

namespace {

UsbError::Type ConvertFromLibUsbErrorToUsbErrorType(libusb_error error) {
  switch (error) {
    case LIBUSB_SUCCESS:
      return UsbError::kSuccess;
    case LIBUSB_ERROR_IO:
      return UsbError::kErrorIO;
    case LIBUSB_ERROR_INVALID_PARAM:
      return UsbError::kErrorInvalidParameter;
    case LIBUSB_ERROR_ACCESS:
      return UsbError::kErrorAccess;
    case LIBUSB_ERROR_NO_DEVICE:
      return UsbError::kErrorNoDevice;
    case LIBUSB_ERROR_NOT_FOUND:
      return UsbError::kErrorNotFound;
    case LIBUSB_ERROR_BUSY:
      return UsbError::kErrorBusy;
    case LIBUSB_ERROR_TIMEOUT:
      return UsbError::kErrorTimeout;
    case LIBUSB_ERROR_OVERFLOW:
      return UsbError::kErrorOverflow;
    case LIBUSB_ERROR_PIPE:
      return UsbError::kErrorPipe;
    case LIBUSB_ERROR_INTERRUPTED:
      return UsbError::kErrorInterrupted;
    case LIBUSB_ERROR_NO_MEM:
      return UsbError::kErrorNoMemory;
    case LIBUSB_ERROR_NOT_SUPPORTED:
      return UsbError::kErrorNotSupported;
    default:
      return UsbError::kErrorOther;
  }
}

}  // namespace

UsbError::UsbError() : type_(kSuccess) {}

UsbError::UsbError(Type type) : type_(type) {}

UsbError::UsbError(libusb_error error)
    : type_(ConvertFromLibUsbErrorToUsbErrorType(error)) {}

bool UsbError::IsSuccess() const {
  return type_ == kSuccess;
}

const char* UsbError::ToString() const {
  switch (type_) {
    case kSuccess:
      return "Success";
    case kErrorIO:
      return "ErrorIO";
    case kErrorInvalidParameter:
      return "ErrorInvalidParameter";
    case kErrorAccess:
      return "ErrorAccess";
    case kErrorNoDevice:
      return "ErrorNoDevice";
    case kErrorNotFound:
      return "ErrorNotFound";
    case kErrorBusy:
      return "ErrorBusy";
    case kErrorTimeout:
      return "ErrorTimeout";
    case kErrorOverflow:
      return "ErrorOverflow";
    case kErrorPipe:
      return "ErrorPipe";
    case kErrorInterrupted:
      return "ErrorInterrupted";
    case kErrorNoMemory:
      return "ErrorNoMemory";
    case kErrorNotSupported:
      return "ErrorNotSupported";
    case kErrorOther:
      return "ErrorOther";
    case kErrorDeviceNotOpen:
      return "ErrorDeviceNotOpen";
    case kErrorTransferAlreadyAllocated:
      return "ErrorTransferAlreadyAllocated";
    case kErrorTransferNotAllocated:
      return "ErrorTransferNotAllocated";
    case kErrorTransferAlreadySubmitted:
      return "ErrorTransferAlreadySubmitted";
    case kErrorTransferNotSubmitted:
      return "ErrorTransferNotSubmitted";
    case kErrorTransferBeingCancelled:
      return "ErrorTransferBeingCancelled";
    default:
      return "Unknown";
  }
}

void UsbError::Clear() {
  type_ = kSuccess;
}

bool UsbError::SetFromLibUsbError(libusb_error error) {
  type_ = ConvertFromLibUsbErrorToUsbErrorType(error);
  return type_ == kSuccess;
}

}  // namespace brillo

std::ostream& operator<<(std::ostream& stream, const brillo::UsbError& error) {
  stream << error.ToString();
  return stream;
}
