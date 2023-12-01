// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "runtime_probe/utils/input_device.h"

#include <limits>
#include <pcrecpp.h>

#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "runtime_probe/proto_bindings/runtime_probe.pb.h"

namespace runtime_probe {

namespace {
constexpr auto kNameEntryPrefix = "Name=";
constexpr auto kSysfsEntryPrefix = "Sysfs=";
const pcrecpp::RE kEventPatternRe(R"(event[\d]+)");

constexpr auto kBitsPerBitmap = sizeof(long) * CHAR_BIT;  // NOLINT(runtime/int)

// Reference:
// https://chromium.googlesource.com/chromiumos/third_party/kernel/+/v4.14/include/uapi/linux/input-event-codes.h
constexpr auto kAbsMtSlot = 0x2f;
constexpr auto kBtnMouse = 0x110;
constexpr auto kBtnToolPen = 0x140;
constexpr auto kBtnTouch = 0x14a;
constexpr auto kBtnStylus = 0x14b;
constexpr auto kBtnStylus2 = 0x14c;

}  // namespace

std::unique_ptr<InputDeviceImpl> InputDeviceImpl::From(
    const std::vector<std::string>& lines) {
  auto input_device = std::make_unique<InputDeviceImpl>();

  // Example lines:
  // I: Bus=1234 Vendor=5678 Product=90ab Version=cdef
  // N: Name="XXXX"
  // P: Phys=XXXX
  // S: Sysfs=/devices/XXXX
  // H: Handlers=event5
  // B: EV=b
  // B: KEY=e520 10000 0 0 0 0
  // B: ABS=663800013000003
  for (const auto& line : lines) {
    if (line.length() < 3) {
      DCHECK_EQ(line.length(), 0);
      continue;
    }
    auto content = base::StringPiece(line).substr(3);
    base::StringPairs keyVals;
    switch (line[0]) {
      case 'I': {
        if (!base::SplitStringIntoKeyValuePairs(content, '=', ' ', &keyVals)) {
          DVLOG(1) << "Failed to parse input devices (" << line[0] << ").";
          return nullptr;
        }
        for (const auto& [key, value] : keyVals) {
          if (key == "Bus")
            input_device->bus = value;
          else if (key == "Vendor")
            input_device->vendor = value;
          else if (key == "Product")
            input_device->product = value;
          else if (key == "Version")
            input_device->version = value;
        }
        break;
      }
      case 'N': {
        if (!base::StartsWith(content, kNameEntryPrefix)) {
          DVLOG(1) << "Failed to parse input devices (" << line[0] << ").";
          return nullptr;
        }
        auto value = content.substr(strlen(kNameEntryPrefix));
        base::TrimString(value, "\"", &input_device->name);
        break;
      }
      case 'S': {
        if (!base::StartsWith(content, kSysfsEntryPrefix)) {
          DVLOG(1) << "Failed to parse input devices (" << line[0] << ").";
          return nullptr;
        }
        input_device->sysfs =
            std::string(content.substr(strlen(kSysfsEntryPrefix)));
        break;
      }
      case 'H': {
        if (!base::SplitStringIntoKeyValuePairs(content, '=', '\n', &keyVals)) {
          DVLOG(1) << "Failed to parse input devices (" << line[0] << ").";
          return nullptr;
        }
        const auto& value = keyVals[0].second;
        const auto& handlers = base::SplitString(
            value, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
        for (const auto& handler : handlers) {
          if (kEventPatternRe.FullMatch(handler)) {
            input_device->event = handler;
            break;
          }
        }
        break;
      }
      case 'B': {
        if (!base::SplitStringIntoKeyValuePairs(content, '=', '\n', &keyVals)) {
          LOG(ERROR) << "Failed to parse input devices (" << line[0] << ").";
          return nullptr;
        }
        const auto& [key, value] = keyVals[0];
        // The bitmaps are represented as several hexadecimal numbers joined by
        // whitespaces.  Each hexadecimal number is a long int, which has
        // different range of values under 32-bit and 64-bit system.  Therefore,
        // we use sizeof(long) to handle such variation.
        const auto& flags = base::SplitStringPiece(
            value, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
        for (const auto& flag : flags) {
          uint64_t output;
          CHECK(base::HexStringToUInt64(flag, &output));
          if (key == "KEY") {
            auto& bits = input_device->ev_key;
            bits = (bits << kBitsPerBitmap) |
                   std::remove_reference<decltype(bits)>::type(output);
          } else if (key == "ABS") {
            auto& bits = input_device->ev_abs;
            bits = (bits << kBitsPerBitmap) |
                   std::remove_reference<decltype(bits)>::type(output);
          } else if (key == "SW") {
            auto& bits = input_device->ev_sw;
            bits = (bits << kBitsPerBitmap) |
                   std::remove_reference<decltype(bits)>::type(output);
          }
        }
        break;
      }
      default: {
        break;
      }
    }
  }
  return input_device;
}

bool InputDeviceImpl::IsStylusDevice() const {
  return ev_key[kBtnStylus] || ev_key[kBtnStylus2] || ev_key[kBtnToolPen];
}

bool InputDeviceImpl::IsTouchpadDevice() const {
  return ev_key[kBtnTouch] && ev_key[kBtnMouse];
}

bool InputDeviceImpl::IsTouchscreenDevice() const {
  return !IsTouchpadDevice() && ev_abs[kAbsMtSlot];
}

InputDevice::Type InputDeviceImpl::type() const {
  if (IsStylusDevice()) {
    return InputDevice::TYPE_STYLUS;
  } else if (IsTouchpadDevice()) {
    return InputDevice::TYPE_TOUCHPAD;
  } else if (IsTouchscreenDevice()) {
    return InputDevice::TYPE_TOUCHSCREEN;
  } else {
    return InputDevice::TYPE_UNKNOWN;
  }
}

}  // namespace runtime_probe
