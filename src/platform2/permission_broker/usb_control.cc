// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/libusb_wrapper.h"
#include "permission_broker/usb_control.h"

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <libusb-1.0/libusb.h>
#include <linux/usb/ch11.h>

#include <base/functional/bind.h>
#include <base/logging.h>
#include <base/strings/stringprintf.h>
#include <base/threading/platform_thread.h>
#include <base/time/time.h>
#include <brillo/message_loops/message_loop.h>

namespace permission_broker {

// TODO(b/110247560): reimplement with a file-based approach (see
// go/usb-power_ctl).
const UsbDeviceInfo kDeviceAllowList[] = {
    // Huddly camera VID and PID.
    UsbDeviceInfo(0x2bd9, 0x0011, 0xEF /* Miscellaneous */),
    // MIMO VUE HD VID and PID.
    // This is a touch controller with a small screen for CFM devices.
    // https://www.mimomonitors.com/products/mimo-vue-hd-display
    UsbDeviceInfo(0x17e9, 0x416d, 0xFF /* Miscellaneous */),
};

std::string DeviceInfoString(uint16_t vid, uint16_t pid) {
  return base::StringPrintf("(vid: 0x%04x, pid: 0x%04x)", vid, pid);
}

// Utility function used to execute either power-on or power-off on all the
// |devices| passed as parameter. The |is_power_on| flag indicates whether the
// devices will be powered off or on when |is_power_on| is set respectively to
// false or true.
bool SetDevicesPowerState(
    const std::vector<std::unique_ptr<UsbDeviceInterface>>& devices,
    bool is_power_on) {
  bool cumulative_success = true;
  for (auto& device : devices) {
    // Get the parent if it is possible.
    auto parent = device->GetParent();
    if (parent == nullptr) {
      LOG(ERROR) << "Unable to find parent for device (" << device->GetInfo()
                 << ")";
      cumulative_success = false;
      continue;
    }

    std::string state = is_power_on ? "on" : "off";
    LOG(INFO) << "Powering " << state << " USB device (" << device->GetInfo()
              << ")";

    // Set the appropriate power state to the device.
    bool success = parent->SetPowerState(is_power_on, device->GetPort());
    if (!success) {
      LOG(WARNING) << "Unable to power " << state << " device ("
                   << device->GetInfo() << ")";
    }
    // Accumulate the success flag so that we can eventually return the
    // cumulative response value.
    cumulative_success = cumulative_success && success;
  }

  return cumulative_success;
}

// This callback is used to delay the powering on of the provided |devices| by
// |delay|. |cumulative_success| is used to finally return the cumulative
// success value determined by cumulatively collecting all the boolean results
// of all power-off and power-on operations.
void PowerOnDevicesCallback(
    base::OnceCallback<void(bool)> callback,
    const std::vector<std::unique_ptr<UsbDeviceInterface>> devices,
    bool cumulative_success) {
  cumulative_success =
      SetDevicesPowerState(devices, true) && cumulative_success;
  std::move(callback).Run(cumulative_success);
}

UsbControl::UsbControl(std::unique_ptr<UsbDeviceManagerInterface> manager)
    : manager_(std::move(manager)) {}

UsbControl::~UsbControl() = default;

bool UsbControl::IsDeviceAllowed(uint16_t vid, uint16_t pid) const {
  return std::find(std::begin(kDeviceAllowList), std::end(kDeviceAllowList),
                   UsbDeviceInfo(vid, pid)) != std::end(kDeviceAllowList);
}

void UsbControl::PowerCycleUsbPorts(base::OnceCallback<void(bool)> callback,
                                    uint16_t vid,
                                    uint16_t pid,
                                    base::TimeDelta delay) {
  if (!IsDeviceAllowed(vid, pid)) {
    LOG(ERROR) << "The device is not allowed for USB control "
               << DeviceInfoString(vid, pid);
    std::move(callback).Run(false);
    return;
  }

  std::vector<std::unique_ptr<UsbDeviceInterface>> devices =
      manager_->GetDevicesByVidPid(vid, pid);
  if (devices.empty()) {
    LOG(WARNING) << "No device with the provided information was found on the "
                 << "system " << DeviceInfoString(vid, pid);
    std::move(callback).Run(false);
    return;
  }

  // Turn off all the devices that were found.
  bool cumulative_success = SetDevicesPowerState(devices, false);

  // After the specified delay, turn all the devices on.
  brillo::MessageLoop::current()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&PowerOnDevicesCallback, std::move(callback),
                     std::move(devices), cumulative_success),
      delay);
}

}  // namespace permission_broker
