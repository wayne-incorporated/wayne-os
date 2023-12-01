// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_UTILS_USB_UTILS_H_
#define DIAGNOSTICS_CROS_HEALTHD_UTILS_USB_UTILS_H_

#include <memory>
#include <string>
#include <utility>

#include <base/files/file_path.h>
#include <brillo/udev/udev_device.h>

#include "diagnostics/mojom/public/cros_healthd_probe.mojom.h"

namespace diagnostics {

// Returns vendor name of a usb device. It uses udev to query the `usb.ids` file
// and fallback to sysfs if doesn't find.
std::string GetUsbVendorName(const std::unique_ptr<brillo::UdevDevice>& device);
// Returns product name of a usb device. Similar to the above method.
std::string GetUsbProductName(
    const std::unique_ptr<brillo::UdevDevice>& device);
// Returns vid and pid of a usb device.
std::pair<uint16_t, uint16_t> GetUsbVidPid(
    const std::unique_ptr<brillo::UdevDevice>& device);
// Returns human readable device class string.
std::string LookUpUsbDeviceClass(const int class_code);
// Determine usb protocol version by checking the root hub version.
ash::cros_healthd::mojom::UsbVersion DetermineUsbVersion(
    const base::FilePath& sysfs_path);
// Returns usb spec speed.
ash::cros_healthd::mojom::UsbSpecSpeed GetUsbSpecSpeed(
    const base::FilePath& sysfs_path);

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_UTILS_USB_UTILS_H_
