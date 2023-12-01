// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_BULK_TRANSFER_H_
#define LIBBRILLO_BRILLO_USB_USB_BULK_TRANSFER_H_

#include "brillo/usb/usb_transfer.h"

#include <brillo/brillo_export.h>

namespace brillo {

class UsbDevice;

// A USB bulk transfer, which extends UsbTransfer.
class BRILLO_EXPORT UsbBulkTransfer : public UsbTransfer {
 public:
  UsbBulkTransfer() = default;
  UsbBulkTransfer(const UsbBulkTransfer&) = delete;
  UsbBulkTransfer& operator=(const UsbBulkTransfer&) = delete;

  ~UsbBulkTransfer() = default;

  // Initializes this USB bulk transfer for the specified |endpoint_address| on
  // |device| with a transfer buffer size of |length| bytes and a timeout value
  // of |timeout| seconds. Returns true on success. If |device| is not open,
  // sets |error_| to UsbError::kErrorDeviceNotOpen and returns false.
  bool Initialize(const UsbDevice& device,
                  uint8_t endpoint_address,
                  int length,
                  uint32_t timeout);
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_USB_USB_BULK_TRANSFER_H_
