// Copyright 2012 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "cros-disks/usb_device_info.h"

#include <vector>

#include <base/check.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>

#include "cros-disks/file_reader.h"
#include "cros-disks/quote.h"

namespace cros_disks {

// A data structure for holding information of a USB device.
struct USBDeviceEntry {
  DeviceType media_type;
};

USBDeviceInfo::USBDeviceInfo() = default;

USBDeviceInfo::~USBDeviceInfo() = default;

DeviceType USBDeviceInfo::GetDeviceMediaType(
    const std::string& vendor_id, const std::string& product_id) const {
  CHECK(!vendor_id.empty()) << "Invalid vendor ID";
  CHECK(!product_id.empty()) << "Invalid product ID";

  std::string id = vendor_id + ":" + product_id;
  std::map<std::string, USBDeviceEntry>::const_iterator map_iterator =
      entries_.find(id);
  if (map_iterator != entries_.end())
    return map_iterator->second.media_type;
  return DeviceType::kUSB;
}

bool USBDeviceInfo::RetrieveFromFile(const std::string& path) {
  entries_.clear();

  FileReader reader;
  if (!reader.Open(base::FilePath(path))) {
    VLOG(1) << "Cannot open USB database " << quote(path);
    return false;
  }

  std::string line;
  while (reader.ReadLine(&line)) {
    if (IsLineSkippable(line))
      continue;

    std::vector<std::string> tokens = base::SplitString(
        line, " ", base::KEEP_WHITESPACE, base::SPLIT_WANT_ALL);
    if (tokens.size() >= 2) {
      USBDeviceEntry& entry = entries_[tokens[0]];
      entry.media_type = ConvertToDeviceMediaType(tokens[1]);
    }
  }
  return true;
}

bool USBDeviceInfo::GetVendorAndProductName(const std::string& ids_file,
                                            const std::string& vendor_id,
                                            const std::string& product_id,
                                            std::string* vendor_name,
                                            std::string* product_name) {
  vendor_name->clear();
  product_name->clear();

  FileReader reader;
  if (!reader.Open(base::FilePath(ids_file))) {
    VLOG(1) << "Cannot open USB database " << quote(ids_file);
    return false;
  }

  bool found_vendor = false;
  std::string line;
  while (reader.ReadLine(&line)) {
    if (IsLineSkippable(line))
      continue;

    std::string id, name;
    // If the target vendor ID is found, search for a matching product ID.
    if (found_vendor) {
      if (line[0] == '\t' && ExtractIdAndName(line.substr(1), &id, &name)) {
        if (id == product_id) {
          *product_name = name;
          break;
        }
        continue;
      }

      // If the line does not contain any product info, assume a new
      // section has started and no product info will be found for the
      // target ID. Return immediately.
      break;
    }

    // Skip forward until the target vendor ID is found.
    if (ExtractIdAndName(line, &id, &name)) {
      if (id == vendor_id) {
        *vendor_name = name;
        found_vendor = true;
      }
    }
  }

  return found_vendor;
}

DeviceType USBDeviceInfo::ConvertToDeviceMediaType(
    const std::string& str) const {
  if (str == "sd") {
    return DeviceType::kSD;
  } else if (str == "mobile") {
    return DeviceType::kMobile;
  } else {
    return DeviceType::kUSB;
  }
}

bool USBDeviceInfo::IsLineSkippable(const std::string& line) const {
  std::string trimmed_line;
  // Trim only ASCII whitespace for now.
  base::TrimWhitespaceASCII(line, base::TRIM_ALL, &trimmed_line);
  return trimmed_line.empty() ||
         base::StartsWith(trimmed_line, "#", base::CompareCase::SENSITIVE);
}

bool USBDeviceInfo::ExtractIdAndName(const std::string& line,
                                     std::string* id,
                                     std::string* name) const {
  if ((line.length() > 6) && base::IsHexDigit(line[0]) &&
      base::IsHexDigit(line[1]) && base::IsHexDigit(line[2]) &&
      base::IsHexDigit(line[3]) && (line[4] == ' ') && (line[5] == ' ')) {
    *id = base::ToLowerASCII(line.substr(0, 4));
    *name = line.substr(6);
    return true;
  }
  return false;
}

}  // namespace cros_disks
