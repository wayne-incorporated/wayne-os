// Copyright 2011 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/disk.h"

#include <algorithm>

namespace cros_disks {
namespace {

const char kUSBDriveName[] = "USB Drive";
const char kSDCardName[] = "SD Card";
const char kOpticalDiscName[] = "Optical Disc";
const char kMobileDeviceName[] = "Mobile Device";
const char kDVDName[] = "DVD";
const char kFallbackPresentationName[] = "External Drive";

}  // namespace

std::string Disk::GetPresentationName() const {
  if (!label.empty()) {
    std::string name = label;
    std::replace(name.begin(), name.end(), '/', '_');
    return name;
  }

  switch (media_type) {
    case DeviceType::kUSB:
      return kUSBDriveName;
    case DeviceType::kSD:
      return kSDCardName;
    case DeviceType::kOpticalDisc:
      return kOpticalDiscName;
    case DeviceType::kMobile:
      return kMobileDeviceName;
    case DeviceType::kDVD:
      return kDVDName;
    default:
      return kFallbackPresentationName;
  }
}

}  // namespace cros_disks
