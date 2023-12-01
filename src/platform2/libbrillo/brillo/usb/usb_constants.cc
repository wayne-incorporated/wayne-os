// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "brillo/usb/usb_constants.h"

#include <base/logging.h>
#include <base/notreached.h>

namespace brillo {

UsbDirection GetUsbDirectionOfEndpointAddress(uint8_t endpoint_address) {
  // The MSB of an endpoint address indicates the direction, and kUsbDirectionIn
  // is effectively a mask to extract the MSB.
  return (endpoint_address & kUsbDirectionIn) == kUsbDirectionIn
             ? kUsbDirectionIn
             : kUsbDirectionOut;
}

const char* UsbDirectionToString(UsbDirection direction) {
  switch (direction) {
    case kUsbDirectionIn:
      return "In";
    case kUsbDirectionOut:
      return "Out";
  }
  NOTREACHED();
  return nullptr;
}

const char* UsbSpeedToString(UsbSpeed speed) {
  switch (speed) {
    case kUsbSpeedUnknown:
      return "Unknown";
    case kUsbSpeedLow:
      return "Low";
    case kUsbSpeedFull:
      return "Full";
    case kUsbSpeedHigh:
      return "High";
    case kUsbSpeedSuper:
      return "Super";
  }
  NOTREACHED();
  return nullptr;
}

const char* UsbTransferTypeToString(UsbTransferType transfer_type) {
  switch (transfer_type) {
    case kUsbTransferTypeControl:
      return "Control";
    case kUsbTransferTypeIsochronous:
      return "Isochronous";
    case kUsbTransferTypeBulk:
      return "Bulk";
    case kUsbTransferTypeInterrupt:
      return "Interrupt";
    case kUsbTransferTypeUnknown:
      return "Unknown";
  }
  NOTREACHED();
  return nullptr;
}

const char* UsbTransferStatusToString(UsbTransferStatus transfer_status) {
  switch (transfer_status) {
    case kUsbTransferStatusCompleted:
      return "Completed";
    case kUsbTransferStatusError:
      return "Error";
    case kUsbTransferStatusTimedOut:
      return "TimedOut";
    case kUsbTransferStatusCancelled:
      return "Cancelled";
    case kUsbTransferStatusStall:
      return "Stall";
    case kUsbTransferStatusNoDevice:
      return "NoDevice";
    case kUsbTransferStatusOverflow:
      return "Overflow";
    case kUsbTransferStatusUnknown:
      return "Unknown";
  }
  NOTREACHED();
  return nullptr;
}

}  // namespace brillo

std::ostream& operator<<(std::ostream& stream, brillo::UsbDirection direction) {
  stream << UsbDirectionToString(direction);
  return stream;
}

std::ostream& operator<<(std::ostream& stream, brillo::UsbSpeed speed) {
  stream << UsbSpeedToString(speed);
  return stream;
}

std::ostream& operator<<(std::ostream& stream,
                         brillo::UsbTransferType transfer_type) {
  stream << UsbTransferTypeToString(transfer_type);
  return stream;
}

std::ostream& operator<<(std::ostream& stream,
                         brillo::UsbTransferStatus transfer_status) {
  stream << UsbTransferStatusToString(transfer_status);
  return stream;
}
