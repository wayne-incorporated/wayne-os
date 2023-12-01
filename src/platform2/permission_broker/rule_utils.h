// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef PERMISSION_BROKER_RULE_UTILS_H_
#define PERMISSION_BROKER_RULE_UTILS_H_

#include <libudev.h>

#include "policy/device_policy.h"

using policy::DevicePolicy;

namespace permission_broker {

// Reads a udev device attribute and assigns it as an unsigned integer to the
// variable at val.
bool GetUIntSysattr(udev_device* device, const char* key, uint32_t* val);

// Check if a USB vendor:product ID pair is in the provided list.
// Entries in the list with |product_id| of 0 match any product with the
// corresponding |vendor_id|.
template <typename Iterator>
bool UsbDeviceListContainsId(Iterator first,
                             Iterator last,
                             uint16_t vendor_id,
                             uint16_t product_id);

// Checks if a device is intended to work with WebHID.
bool IsDeviceAllowedWebHID(udev_device* device);

}  // namespace permission_broker

#endif  // PERMISSION_BROKER_RULE_UTILS_H_
