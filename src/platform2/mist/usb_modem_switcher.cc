// Copyright 2013 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "mist/usb_modem_switcher.h"

#include <memory>

#include <base/check.h>
#include <base/functional/bind.h>
#include <brillo/usb/usb_device_event_notifier.h>

#include "mist/config_loader.h"
#include "mist/context.h"
#include "mist/proto_bindings/usb_modem_info.pb.h"
#include "mist/usb_modem_switch_context.h"
#include "mist/usb_modem_switch_operation.h"

namespace mist {

// TODO(benchan): Add unit tests for UsbModemSwitcher.

UsbModemSwitcher::UsbModemSwitcher(Context* context) : context_(context) {
  CHECK(context_);
}

UsbModemSwitcher::~UsbModemSwitcher() {
  context_->usb_device_event_notifier()->RemoveObserver(this);
}

void UsbModemSwitcher::Start() {
  context_->usb_device_event_notifier()->AddObserver(this);
  context_->usb_device_event_notifier()->ScanExistingDevices();
}

void UsbModemSwitcher::OnSwitchOperationCompleted(
    UsbModemSwitchOperation* operation, bool success) {
  CHECK(operation);
  delete operation;
}

void UsbModemSwitcher::OnUsbDeviceAdded(const std::string& sys_path,
                                        uint8_t bus_number,
                                        uint8_t device_address,
                                        uint16_t vendor_id,
                                        uint16_t product_id) {
  const UsbModemInfo* modem_info =
      context_->config_loader()->GetUsbModemInfo(vendor_id, product_id);
  if (!modem_info)
    return;  // Ignore an unsupported device.

  auto switch_context = std::make_unique<UsbModemSwitchContext>(
      sys_path, bus_number, device_address, vendor_id, product_id, modem_info);
  CHECK(switch_context);

  UsbModemSwitchOperation* operation =
      new UsbModemSwitchOperation(context_, switch_context.release());
  CHECK(operation);

  // The operation object will be deleted in OnSwitchOperationCompleted().
  operation->Start(base::BindOnce(&UsbModemSwitcher::OnSwitchOperationCompleted,
                                  base::Unretained(this)));
}

void UsbModemSwitcher::OnUsbDeviceRemoved(const std::string& sys_path) {
  // UsbModemSwitcher does not need to handle device removal.
}

}  // namespace mist
