// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This header contains functions that shouldn't be used outside of util.cc
// and util_test.cc primarily to abstract libusbguard related types and symbols,
// but still allow for them to be used in unit tests.

#ifndef USB_BOUNCER_UTIL_INTERNAL_H_
#define USB_BOUNCER_UTIL_INTERNAL_H_

#include "usb_bouncer/util.h"

#include <string>

#include <usbguard/Rule.hpp>

namespace usb_bouncer {

enum class UMADeviceClass {
  kApp = 0,
  kAudio = 1,
  kAV = 2,
  kCard = 3,
  kComm = 4,
  kHealth = 5,
  kHID = 6,
  kHub = 7,
  kImage = 8,
  kMisc = 9,
  kOther = 10,
  kPhys = 11,
  kPrint = 12,
  kSec = 13,
  kStorage = 14,
  kVendor = 15,
  kVideo = 16,
  kWireless = 17,
  kMaxValue = kWireless,
};

const std::string to_string(UMADeviceClass device_class);
const std::string to_string(UMADeviceRecognized recognized);
const std::string to_string(UMAPortType port);
std::ostream& operator<<(std::ostream& out, UMADeviceClass device_class);
std::ostream& operator<<(std::ostream& out, UMADeviceRecognized recognized);
std::ostream& operator<<(std::ostream& out, UMAPortType port);

// libusbguard uses exceptions, so this converts the exception case to a return
// value that tests as bool false.
usbguard::Rule GetRuleFromString(const std::string& to_parse);

UMADeviceClass GetClassFromRule(const usbguard::Rule& rule);

}  // namespace usb_bouncer

#endif  // USB_BOUNCER_UTIL_INTERNAL_H_
