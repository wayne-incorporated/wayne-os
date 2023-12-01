// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "shill/device_id.h"

#include <inttypes.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

namespace shill {

namespace {

// Attribute file in sysfs for PCI devices that indicate whether the PCI device
// is internal or external (0=internal, 1=external). This works because the
// firmware tags the external facing PCI ports by a flag that the kernel looks
// at, to determine whether a device is internal or external. This sysfs
// is something we couldnt reach agreement upstream with yet, and are carrying
// ourselves currently. Ref:
// https://chromium-review.googlesource.com/c/chromiumos/third_party/kernel/+/2511510
constexpr char kExternalAttribute[] = "untrusted";

// Reads a file containing a string device ID and normalizes it by trimming
// whitespace and converting to lowercase.
bool ReadDeviceIdFile(const base::FilePath& path, std::string* out_id) {
  DCHECK(out_id);
  std::string contents;
  if (!base::ReadFileToString(path, &contents))
    return false;

  *out_id = base::CollapseWhitespaceASCII(base::ToLowerASCII(contents), true);
  return true;
}

bool HextetToUInt16(const std::string& input, uint16_t* output) {
  DCHECK(output);
  std::vector<uint8_t> bytes;
  if (!base::HexStringToBytes(input, &bytes))
    return false;

  if (bytes.size() != 2)
    return false;

  *output = bytes[0] << 8 | bytes[1];
  return true;
}

bool HexToUInt16(const std::string& input, uint16_t* output) {
  DCHECK(output);
  if (base::StartsWith(input, "0x", base::CompareCase::INSENSITIVE_ASCII)) {
    return HextetToUInt16(input.substr(2), output);
  }
  return HextetToUInt16(input, output);
}

std::unique_ptr<DeviceId> ReadDeviceId(DeviceId::BusType bus_type,
                                       const base::FilePath& vendor_path,
                                       const base::FilePath& product_path) {
  std::string vendor_id, product_id;
  uint16_t parsed_vendor_id, parsed_product_id;

  if (!ReadDeviceIdFile(vendor_path, &vendor_id) ||
      !HexToUInt16(vendor_id, &parsed_vendor_id)) {
    return std::make_unique<DeviceId>(bus_type);
  }

  if (!ReadDeviceIdFile(product_path, &product_id) ||
      !HexToUInt16(product_id, &parsed_product_id)) {
    return std::make_unique<DeviceId>(bus_type, parsed_vendor_id);
  }

  return std::make_unique<DeviceId>(bus_type, parsed_vendor_id,
                                    parsed_product_id);
}

}  // namespace

// static
std::unique_ptr<DeviceId> DeviceId::CreateFromSysfs(
    const base::FilePath& syspath) {
  if (syspath.empty()) {
    return nullptr;
  }

  base::FilePath subsystem;
  if (!base::ReadSymbolicLink(syspath.Append("subsystem"), &subsystem)) {
    return nullptr;
  }

  std::string bus_type = subsystem.BaseName().value();
  if (bus_type == "pci") {
    auto dev = ReadDeviceId(DeviceId::BusType::kPci, syspath.Append("vendor"),
                            syspath.Append("device"));

    std::string is_external;
    if (base::ReadFileToString(syspath.Append(kExternalAttribute),
                               &is_external) &&
        !is_external.empty()) {
      is_external = base::CollapseWhitespaceASCII(is_external, true);
      if (is_external == "0") {
        dev->location_type_ = LocationType::kInternal;
      } else {
        dev->location_type_ = LocationType::kExternal;
      }
    }
    return dev;
  } else if (bus_type == "usb") {
    return ReadDeviceId(DeviceId::BusType::kUsb, syspath.Append("idVendor"),
                        syspath.Append("idProduct"));
  }
  return nullptr;
}

std::string DeviceId::AsString() const {
  const char* bus_name;
  switch (bus_type_) {
    case BusType::kUsb:
      bus_name = "usb";
      break;
    case BusType::kPci:
      bus_name = "pci";
      break;
    case BusType::kSoc:
      bus_name = "soc";
      break;
  }

  const char* loc;
  if (location_type_ == LocationType::kExternal)
    loc = " (External)";
  else if (location_type_ == LocationType::kInternal)
    loc = " (Internal)";
  else
    loc = "";

  if (!vendor_id_.has_value()) {
    return base::StringPrintf("%s:*:*%s", bus_name, loc);
  }

  if (!product_id_.has_value()) {
    return base::StringPrintf("%s:%04" PRIx16 ":*%s", bus_name,
                              vendor_id_.value(), loc);
  }

  return base::StringPrintf("%s:%04" PRIx16 ":%04" PRIx16 "%s", bus_name,
                            vendor_id_.value(), product_id_.value(), loc);
}

bool DeviceId::Match(const DeviceId& pattern) const {
  if (bus_type_ != pattern.bus_type_) {
    return false;
  }

  // Check if match is specifically desired based on location type.
  if (pattern.location_type_.has_value() &&
      location_type_ != pattern.location_type_) {
    return false;
  }

  // If |pattern| vendor id is *, then they don't have to match VID and PID
  // values.
  if (!pattern.vendor_id_.has_value()) {
    return true;
  }
  // If |this| vendor id is *, then it can not match to |pattern| with specific
  // vendor id.
  if (!vendor_id_.has_value() ||
      vendor_id_.value() != pattern.vendor_id_.value()) {
    return false;
  }

  // If |pattern| product id is *, then they don't have to match PID values.
  if (!pattern.product_id_.has_value()) {
    return true;
  }
  // If |this| product id is *, then it can not match to |pattern| with specific
  // product id.
  return product_id_.has_value() &&
         product_id_.value() == pattern.product_id_.value();
}

std::ostream& operator<<(std::ostream& stream, const DeviceId& device_id) {
  return stream << device_id.AsString();
}

}  // namespace shill
