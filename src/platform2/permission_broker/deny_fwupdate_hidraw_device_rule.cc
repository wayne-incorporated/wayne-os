// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "permission_broker/deny_fwupdate_hidraw_device_rule.h"

#include <libudev.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "base/files/file_path.h"
#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_split.h"
#include "base/strings/string_util.h"

namespace {

const int kElanVendorId = 0x04f3;
const int kMelfasVendorId = 0x1fd2;

// Structure that holds a map of vendor IDs and a list of the blocked product ID
// ranges. These ranges are inclusive.
const permission_broker::RangeListMap kFwUpdateDevices = {
    // Block ELAN touchscreens PID 0x2000 - 0x2FFF and 0x4000 - 0x4FFF. 0x0732
    // is the PID for a device in recovery mode.
    {kElanVendorId, {{0x2000, 0x2fff}, {0x4000, 0x4fff}, {0x0732, 0x0732}}},
    // Melfas USB touchscreen PID 0x8103.
    {kMelfasVendorId, {{0x8103, 0x8103}}},
};

}  // namespace

namespace permission_broker {

DenyFwUpdateHidrawDeviceRule::DenyFwUpdateHidrawDeviceRule()
    : HidrawSubsystemUdevRule("DenyFwUpdateHidrawDeviceRule") {}

Rule::Result DenyFwUpdateHidrawDeviceRule::ProcessHidrawDevice(
    struct udev_device* device) {
  const char* devpath = udev_device_get_devpath(device);
  return IsFwUpdateDevice(devpath, kFwUpdateDevices) ? Rule::DENY
                                                     : Rule::IGNORE;
}

// The vendor and device ID are not in the udev properties. They need to be
// parsed out of the device path:
// e.g. i2c-7/i2c-ELAN900C:00/0018:04F3:2A03.0001/hidraw/hidraw0. The
// important part of the path is 0018:04F3:2A03.0001 where 04F3 is the vendor
// ID and 2A03 is the product ID.
bool DenyFwUpdateHidrawDeviceRule::IsFwUpdateDevice(
    const char* path, const RangeListMap& fwDevices) {
  if (!path) {
    return false;
  }

  // Split the path by directories.
  std::vector<std::string> dirs = base::FilePath(path).GetComponents();

  for (const auto& dir : dirs) {
    // Split the path by colons (:). We are searching for the pattern:
    // ####:####:####.####
    // All devices that match this pattern need to be checked to ensure that
    // none are disallowed.
    std::vector<std::string> chunks =
        base::SplitString(dir, ":", base::WhitespaceHandling::TRIM_WHITESPACE,
                          base::SplitResult::SPLIT_WANT_NONEMPTY);

    if (chunks.size() != 3) {
      continue;
    }

    // The vendor ID is the second hex value in the sequence.
    int vendor_id;
    if (!base::HexStringToInt(chunks[1], &vendor_id)) {
      continue;
    }

    // The product ID is the third hex value in the sequence. The period and
    // trailing numbers also need to be trimmed.
    std::string::size_type pos = chunks[2].find('.');
    int product_id;
    if (!base::HexStringToInt(chunks[2].substr(0, pos), &product_id)) {
      continue;
    }

    if (fwDevices.count(vendor_id) != 1) {
      continue;
    }

    for (const auto& range : fwDevices.at(vendor_id)) {
      if (product_id >= range.min && product_id <= range.max) {
        return true;
      }
    }
  }

  return false;
}

}  // namespace permission_broker
