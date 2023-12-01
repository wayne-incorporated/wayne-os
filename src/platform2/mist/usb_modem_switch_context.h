// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef MIST_USB_MODEM_SWITCH_CONTEXT_H_
#define MIST_USB_MODEM_SWITCH_CONTEXT_H_

#include <stdint.h>

#include <string>

namespace mist {

class Context;
class UsbModemInfo;

// A USB modem switch context, which holds the information about the USB device
// to undergo a modem switch operation.
class UsbModemSwitchContext {
 public:
  UsbModemSwitchContext();

  // Constructs a UsbModemSwitchContext object with the following information
  // about the USB device to undergo a modem switch operation:
  //   |sysfs_path|: the sysfs path of the device
  //   |bus_number|: the number of the bus that the device is connected to
  //   |device_address|: the address of the device on the bus
  //   |vendor_id|: USB vendor ID of the device
  //   |product_id|: USB product ID of the device
  //   |modem_info|: a raw pointer to a UsbModemInfo object as that contains the
  //                 information about how to switch the device to the modem
  //                 mode. The ownership of |modem_info| is not transferred, and
  //                 thus it should outlive this object.
  UsbModemSwitchContext(const std::string& sys_path,
                        uint8_t bus_number,
                        uint8_t device_address,
                        uint16_t vendor_id,
                        uint16_t product_id,
                        const UsbModemInfo* modem_info);
  UsbModemSwitchContext(const UsbModemSwitchContext&) = delete;
  UsbModemSwitchContext& operator=(const UsbModemSwitchContext&) = delete;

  ~UsbModemSwitchContext() = default;

  // Initializes this switch context object with the information obtained from
  // the device on the sysfs path |sys_path|. This method uses the helper
  // objects provided by |context|. Returns true if the device on |sys_path| is
  // supported for modem switch operation.
  bool InitializeFromSysPath(const Context* context,
                             const std::string& sys_path);

  const std::string& sys_path() const { return sys_path_; }
  uint8_t bus_number() const { return bus_number_; }
  uint8_t device_address() const { return device_address_; }
  uint16_t vendor_id() const { return vendor_id_; }
  uint16_t product_id() const { return product_id_; }
  const UsbModemInfo* modem_info() const { return modem_info_; }

 private:
  std::string sys_path_;
  uint8_t bus_number_;
  uint8_t device_address_;
  uint16_t vendor_id_;
  uint16_t product_id_;
  const UsbModemInfo* modem_info_;
};

}  // namespace mist

#endif  // MIST_USB_MODEM_SWITCH_CONTEXT_H_
