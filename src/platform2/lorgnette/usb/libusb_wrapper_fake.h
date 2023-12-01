// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_USB_LIBUSB_WRAPPER_FAKE_H_
#define LORGNETTE_USB_LIBUSB_WRAPPER_FAKE_H_

#include <memory>
#include <vector>

#include "lorgnette/usb/libusb_wrapper.h"
#include "lorgnette/usb/usb_device.h"

namespace lorgnette {

class LibusbWrapperFake : public LibusbWrapper {
 public:
  LibusbWrapperFake() = default;
  LibusbWrapperFake(const LibusbWrapperFake&) = delete;
  LibusbWrapperFake& operator=(const LibusbWrapperFake&) = delete;
  ~LibusbWrapperFake() override = default;

  std::vector<std::unique_ptr<UsbDevice>> GetDevices() override;

  void SetDevices(std::vector<std::unique_ptr<UsbDevice>> devices);

 private:
  std::vector<std::unique_ptr<UsbDevice>> devices_;
};

}  // namespace lorgnette

#endif  // LORGNETTE_USB_LIBUSB_WRAPPER_FAKE_H_
