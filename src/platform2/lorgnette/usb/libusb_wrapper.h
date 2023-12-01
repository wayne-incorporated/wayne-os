// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_USB_LIBUSB_WRAPPER_H_
#define LORGNETTE_USB_LIBUSB_WRAPPER_H_

#include <memory>
#include <vector>

#include "lorgnette/usb/usb_device.h"

namespace lorgnette {

class LibusbWrapper {
 public:
  LibusbWrapper() = default;
  LibusbWrapper(const LibusbWrapper&) = delete;
  LibusbWrapper& operator=(const LibusbWrapper&) = delete;
  virtual ~LibusbWrapper() = default;

  virtual std::vector<std::unique_ptr<UsbDevice>> GetDevices() = 0;
};

}  // namespace lorgnette

#endif  // LORGNETTE_USB_LIBUSB_WRAPPER_H_
