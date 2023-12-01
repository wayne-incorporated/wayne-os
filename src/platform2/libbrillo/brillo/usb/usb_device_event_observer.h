// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBBRILLO_BRILLO_USB_USB_DEVICE_EVENT_OBSERVER_H_
#define LIBBRILLO_BRILLO_USB_USB_DEVICE_EVENT_OBSERVER_H_

#include <stdint.h>

#include <string>

#include <base/observer_list_types.h>

namespace brillo {

// An interface class for observing USB device events from
// UsbDeviceEventNotifier.
class UsbDeviceEventObserver : public base::CheckedObserver {
 public:
  // Invoked when a USB device is added to the system.
  virtual void OnUsbDeviceAdded(const std::string& sys_path,
                                uint8_t bus_number,
                                uint8_t device_address,
                                uint16_t vendor_id,
                                uint16_t product_id) = 0;
  // Invoked when a USB device is removed from the system.
  virtual void OnUsbDeviceRemoved(const std::string& sys_path) = 0;

 protected:
  UsbDeviceEventObserver() = default;
  UsbDeviceEventObserver(const UsbDeviceEventObserver&) = delete;
  UsbDeviceEventObserver& operator=(const UsbDeviceEventObserver&) = delete;

  virtual ~UsbDeviceEventObserver() = default;
};

}  // namespace brillo

#endif  // LIBBRILLO_BRILLO_USB_USB_DEVICE_EVENT_OBSERVER_H_
