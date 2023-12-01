// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debugd/src/helpers/modetest_helper_utils.h"

#include <algorithm>

#include <base/strings/stringprintf.h>
#include <re2/re2.h>

namespace debugd {
namespace modetest_helper_utils {
namespace {
// Looks like "    1 EDID:"
constexpr char kEDIDPropertyRegex[] = R"(^\s+\d+ EDID:$)";
constexpr char kValueRegex[] = R"(^\s+value:$)";
// The EDID is printed as a hex dump over several lines, each line containing
// the contents of 16 bytes. The first 16 bytes are broken down as follows:
//   uint64_t fixed_pattern;      // Always 00 FF FF FF FF FF FF 00.
//   uint16_t manufacturer_id;    // Manufacturer ID, encoded as PNP IDs.
//   uint16_t product_code;       // Manufacturer product code, little-endian.
//   uint32_t serial_number;      // Serial number, little-endian.
// Source: https://en.wikipedia.org/wiki/EDID#EDID_1.3_data_format
//
// The subsequent regex looks for the fixed pattern followed by two 32-bit
// fields (manufacturer + product, serial number).
constexpr char kEDIDSerialRegex[] = R"(^\s+(00f{12}00[0-9a-f]{8}[0-9a-f]{8}))";
// Blob value is a sequence of at least one hex digit.
constexpr char kBlobRegex[] = R"(^\s+[0-9a-f]+$)";

RE2 GetPropertyRegex(const std::string& property_name) {
  constexpr char kEDIDPropertyRegex[] = R"(^\s+\d+ %s:$)";
  std::string property_regex =
      base::StringPrintf(kEDIDPropertyRegex, property_name.c_str());
  return RE2(property_regex.c_str());
}
}  // namespace

EDIDFilter::EDIDFilter() : saw_edid_property_(false), saw_value_(false) {}

void EDIDFilter::ProcessLine(std::string& line) {
  if (!saw_edid_property_) {
    saw_edid_property_ = RE2::FullMatch(line, kEDIDPropertyRegex);
  } else if (!saw_value_) {
    saw_value_ = RE2::FullMatch(line, kValueRegex);
  } else {
    re2::StringPiece s;
    // The first line in the EDID blob value should have the serial number
    // which we want to filter out.
    if (RE2::PartialMatch(line, kEDIDSerialRegex, &s)) {
      // Find the end of this match in |line|.
      auto it = std::search(line.rbegin(), line.rend(), s.rbegin(), s.rend());
      if (it != line.rend()) {
        // Clear the serial number, which is the first 8 characters.
        std::fill_n(it, 8, '0');
      }
    }
    // Reset these since we don't want to look at anymore of the blob
    // after we've looked at the first line. If we failed to find a
    // valid EDID (i.e. the match fails) we want to reset the state machine
    // as well.
    saw_value_ = false;
    saw_edid_property_ = false;
  }
}

// BlobFilter will remove the blob value of the specified property.
BlobFilter::BlobFilter(const std::string& property_name)
    : saw_property_(false),
      saw_value_(false),
      property_pattern_(GetPropertyRegex(property_name)) {}

bool BlobFilter::ProcessLine(const std::string& line) {
  if (!saw_property_) {
    saw_property_ = RE2::FullMatch(line, property_pattern_);
  } else if (!saw_value_) {
    saw_value_ = RE2::FullMatch(line, kValueRegex);
  } else {
    // While scanning the property's value, return |false| for every line
    // that looks like a blob, indicating the line should be skipped.
    if (RE2::FullMatch(line, kBlobRegex)) {
      return false;
    } else {
      // Upon finding the first non-blob line, reset the state machine.
      saw_value_ = false;
      saw_property_ = false;
    }
  }
  return true;
}
}  // namespace modetest_helper_utils
}  // namespace debugd
