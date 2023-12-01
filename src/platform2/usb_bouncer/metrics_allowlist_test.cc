// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/test/bind.h>
#include <gtest/gtest.h>

#include "usb_bouncer/metrics_allowlist.h"
#include "usb_bouncer/util_internal.h"

namespace usb_bouncer {

namespace {

const policy::DevicePolicy::UsbDeviceId kBlockedDevices[] = {
    /* No VID match */
    {0x8945, 0x7102},
    {0xb489, 0x0749},
    /* No PID match */
    {0x03F0, 0x5425},
    {0x2109, 0x5120},
    /* No VID or PID match */
    {0x0054, 0xd543},
    {0x4352, 0x8665},
};

}  // namespace

// Test to check the DeviceInMetricsAllowlist function is able to find all
// allowed VID/PIDs in the allowlist.
TEST(MetricsAllowlistTest, CheckAllowedDevices) {
  for (policy::DevicePolicy::UsbDeviceId device :
       usb_bouncer::kMetricsAllowlist) {
    EXPECT_TRUE(usb_bouncer::DeviceInMetricsAllowlist(device.vendor_id,
                                                      device.product_id));
  }
}

// Test to check the DeviceInMetricsAllowlist function is able to conclude that
// none of the device in kBlockedDevices are in the allowlist.
TEST(MetricsAllowlistTest, CheckBlockedDevices) {
  for (policy::DevicePolicy::UsbDeviceId device : kBlockedDevices) {
    EXPECT_FALSE(usb_bouncer::DeviceInMetricsAllowlist(device.vendor_id,
                                                       device.product_id));
  }
}

}  // namespace usb_bouncer
