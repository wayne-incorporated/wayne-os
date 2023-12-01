// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_USB_MODEM_SWITCHER_H_
#define MIST_USB_MODEM_SWITCHER_H_

#include <stdint.h>

#include <string>

#include <brillo/usb/usb_device_event_observer.h>

namespace mist {

class Context;
class UsbModemSwitchOperation;

// A USB modem switcher, which initiates a modem switch operation for each
// supported USB device that currently exists on the system, or when a supported
// USB device is added to the system.
class UsbModemSwitcher : public brillo::UsbDeviceEventObserver {
 public:
  // Constructs a UsbModemSwitcher object by taking a raw pointer to a Context
  // object as |context|. The ownership of |context| is not transferred, and
  // thus it should outlive this object.
  explicit UsbModemSwitcher(Context* context);
  UsbModemSwitcher(const UsbModemSwitcher&) = delete;
  UsbModemSwitcher& operator=(const UsbModemSwitcher&) = delete;

  ~UsbModemSwitcher();

  // Starts scanning existing USB devices on the system and monitoring new USB
  // devices being added to the system. Initiates a switch operation for each
  // supported device.
  void Start();

 private:
  // Invoked upon the completion of a switch operation where |success| indicates
  // whether the operation completed successfully or not. |operation| is deleted
  // in this callback.
  void OnSwitchOperationCompleted(UsbModemSwitchOperation* operation,
                                  bool success);

  // Implements UsbDeviceEventObserver.
  void OnUsbDeviceAdded(const std::string& sys_path,
                        uint8_t bus_number,
                        uint8_t device_address,
                        uint16_t vendor_id,
                        uint16_t product_id) override;
  void OnUsbDeviceRemoved(const std::string& sys_path) override;

  Context* const context_;
};

}  // namespace mist

#endif  // MIST_USB_MODEM_SWITCHER_H_
