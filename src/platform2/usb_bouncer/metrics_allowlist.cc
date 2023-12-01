// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "usb_bouncer/metrics_allowlist.h"

#include <algorithm>
#include <iterator>

namespace usb_bouncer {

bool DeviceComp(policy::DevicePolicy::UsbDeviceId dev1,
                policy::DevicePolicy::UsbDeviceId dev2) {
  // Allowlist entries are first sorted by VID.
  if (dev1.vendor_id < dev2.vendor_id)
    return true;
  else if (dev1.vendor_id > dev2.vendor_id)
    return false;

  // If 2 entries have the same VID, they are sorted by PID.
  return (dev1.product_id < dev2.product_id);
}

bool DeviceInMetricsAllowlist(uint16_t vendor_id, uint16_t product_id) {
  policy::DevicePolicy::UsbDeviceId device = {vendor_id, product_id};
  return std::binary_search(std::begin(kMetricsAllowlist),
                            std::end(kMetricsAllowlist), device, DeviceComp);
}

}  // namespace usb_bouncer
