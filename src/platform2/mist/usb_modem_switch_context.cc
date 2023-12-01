// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mist/usb_modem_switch_context.h"

#include <memory>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <brillo/udev/udev.h>
#include <brillo/udev/udev_device.h>
#include <brillo/usb/usb_device_event_notifier.h>

#include "mist/config_loader.h"
#include "mist/context.h"
#include "mist/proto_bindings/usb_modem_info.pb.h"

namespace mist {

UsbModemSwitchContext::UsbModemSwitchContext()
    : bus_number_(0),
      device_address_(0),
      vendor_id_(0),
      product_id_(0),
      modem_info_(nullptr) {}

UsbModemSwitchContext::UsbModemSwitchContext(const std::string& sys_path,
                                             uint8_t bus_number,
                                             uint8_t device_address,
                                             uint16_t vendor_id,
                                             uint16_t product_id,
                                             const UsbModemInfo* modem_info)
    : sys_path_(sys_path),
      bus_number_(bus_number),
      device_address_(device_address),
      vendor_id_(vendor_id),
      product_id_(product_id),
      modem_info_(modem_info) {}

bool UsbModemSwitchContext::InitializeFromSysPath(const Context* context,
                                                  const std::string& sys_path) {
  CHECK(context);

  std::unique_ptr<brillo::UdevDevice> device(
      context->udev()->CreateDeviceFromSysPath(sys_path.c_str()));
  if (!device) {
    VLOG(1) << "Could not find device '" << sys_path << "'.";
    return false;
  }

  uint8_t bus_number;
  uint8_t device_address;
  uint16_t vendor_id;
  uint16_t product_id;
  if (!context->usb_device_event_notifier()->GetDeviceAttributes(
          device.get(), &bus_number, &device_address, &vendor_id,
          &product_id)) {
    VLOG(1) << "Could not get attributes of device '" << sys_path << "'.";
    return false;
  }

  const UsbModemInfo* modem_info =
      context->config_loader()->GetUsbModemInfo(vendor_id, product_id);
  if (!modem_info) {
    VLOG(1) << "Could not find USB modem info for device '" << sys_path << "'.";
    return false;
  }

  sys_path_ = sys_path;
  bus_number_ = bus_number;
  device_address_ = device_address;
  vendor_id_ = vendor_id;
  product_id_ = product_id;
  modem_info_ = modem_info;

  VLOG(1) << base::StringPrintf(
      "Initialized UsbModemSwitchContext("
      "SysPath=%s, "
      "BusNumber=%03u, "
      "DeviceAddress=%03u, "
      "VendorId=0x%04x, "
      "ProductId=0x%04x)",
      sys_path_.c_str(), bus_number_, device_address_, vendor_id_, product_id_);
  return true;
}

}  // namespace mist
