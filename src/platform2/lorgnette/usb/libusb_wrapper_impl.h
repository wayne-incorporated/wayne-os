// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LORGNETTE_USB_LIBUSB_WRAPPER_IMPL_H_
#define LORGNETTE_USB_LIBUSB_WRAPPER_IMPL_H_

#include <memory>
#include <vector>

#include <libusb.h>

#include "lorgnette/usb/libusb_wrapper.h"
#include "lorgnette/usb/usb_device.h"

namespace lorgnette {

// Implementation of the LibusbWrapper interface that uses real libusb.
class LibusbWrapperImpl : public LibusbWrapper {
 public:
  LibusbWrapperImpl(const LibusbWrapperImpl&) = delete;
  LibusbWrapperImpl& operator=(const LibusbWrapperImpl&) = delete;
  ~LibusbWrapperImpl() override;

  // May return nullptr if libusb initialization fails.  Caller
  // must check the result.
  static std::unique_ptr<LibusbWrapperImpl> Create();

  std::vector<std::unique_ptr<UsbDevice>> GetDevices() override;

 private:
  explicit LibusbWrapperImpl(libusb_context* context);

  libusb_context* context_;
};

}  // namespace lorgnette

#endif  // LORGNETTE_USB_LIBUSB_WRAPPER_IMPL_H_
