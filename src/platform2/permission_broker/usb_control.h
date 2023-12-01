// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_USB_CONTROL_H_
#define PERMISSION_BROKER_USB_CONTROL_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include <libusb-1.0/libusb.h>

#include <base/time/time.h>
#include <brillo/dbus/dbus_object.h>

#include "permission_broker/libusb_wrapper.h"

namespace permission_broker {

// This class encapsulates the logic used to interact with the VBUS subsystem to
// control the power state of USB devices.
class UsbControl {
 public:
  explicit UsbControl(std::unique_ptr<UsbDeviceManagerInterface> manager);
  UsbControl(const UsbControl&) = delete;
  UsbControl& operator=(const UsbControl&) = delete;

  ~UsbControl();

  // Based on |vid| and |pid| of a USB device, this function determines if the
  // device type can be controlled by the API. The UsbControl implements an
  // allow/deny mechanism, meaning that if a device is *not* allowed, it
  // cannot be controlled.
  bool IsDeviceAllowed(uint16_t vid, uint16_t pid) const;
  // When called, this function will find all the USB devices identified by
  // |vid| and |pid| and will try to power-cycle them using the VBUS subsystem.
  // The |delay| determines the delay between powering all the devices found on
  // and powering them all off.
  void PowerCycleUsbPorts(base::OnceCallback<void(bool)> callback,
                          uint16_t vid,
                          uint16_t pid,
                          base::TimeDelta delay);

 private:
  std::unique_ptr<UsbDeviceManagerInterface> manager_ = nullptr;
};

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_USB_CONTROL_H_
