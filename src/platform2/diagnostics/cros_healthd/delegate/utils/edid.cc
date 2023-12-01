// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "diagnostics/cros_healthd/delegate/utils/edid.h"

#include <stdint.h>

#include <algorithm>
#include <numeric>
#include <string>
#include <vector>

#include <base/strings/stringprintf.h>

namespace diagnostics {

namespace {

constexpr int kSize = sizeof(EdidRaw);
constexpr int kDescriptorDataSize = 13;
constexpr uint8_t kValidHeader[] = "\x00\xff\xff\xff\xff\xff\xff\x00";
constexpr int kValidHeaderLen = 8;
constexpr int kSupportedVersion = 0x01;

bool isValidEdid(const EdidRaw& edid_raw) {
  // Invalid header.
  if (!std::equal(kValidHeader, kValidHeader + kValidHeaderLen,
                  edid_raw.header))
    return false;

  // Unsupported EDID version.
  if (edid_raw.version != kSupportedVersion)
    return false;

  // Non-pixel clock format is not supported.
  if (!edid_raw.pixel_clock)
    return false;
  return true;
}

std::optional<std::string> ExtractString(const uint8_t* data) {
  static char ret[kDescriptorDataSize];
  bool seen_newline = false;
  memset(ret, 0, sizeof(ret));

  for (int i = 0; i < kDescriptorDataSize; i++) {
    if (isgraph(data[i])) {
      ret[i] = data[i];
    } else if (!seen_newline) {
      if (data[i] == 0x0a) {
        seen_newline = true;
        // Find one or more trailing spaces.
        if (i > 0 && ret[i - 1] == 0x20) {
          return std::nullopt;
        }
      } else if (data[i] == 0x20) {
        ret[i] = data[i];
      } else {
        return std::nullopt;
      }
    } else if (data[i] != 0x20) {
      return std::nullopt;
    }
  }

  // Find trailing spaces.
  if (!seen_newline && ret[kDescriptorDataSize - 1] == 0x20)
    return std::nullopt;
  return ret;
}

}  // namespace

std::optional<EdidInfo> Edid::From(const std::vector<uint8_t>& blob) {
  // Incomplete data.
  if (blob.size() < kSize)
    return std::nullopt;

  // Sum of all 128 bytes should equal 0 (mod 256).
  if ((std::accumulate(blob.begin(), blob.begin() + kSize, 0) & 0xff) != 0)
    return std::nullopt;

  EdidRaw edid_raw;
  std::copy(blob.begin(), blob.begin() + kSize,
            reinterpret_cast<uint8_t*>(&edid_raw));
  if (!isValidEdid(edid_raw))
    return std::nullopt;

  return Edid(edid_raw);
}

Edid::Edid(const EdidRaw& edid_raw) {
  // The manufacturer name is a big-endian 16-bit value consisting of three
  // 5-bit compressed ASCII codes, such as 'A' = 00001 and 'Z' = 11010.
  // Format of |edid_raw.mfg_id|:
  //   Bit 15: Reserved.
  //   Bits 14–10: First letter.
  //   Bits 9–5: Second letter.
  //   Bits 4–0: Third letter.
  uint16_t manufacturer_code = (edid_raw.mfg_id[0] << 8) | edid_raw.mfg_id[1];
  manufacturer = "";
  for (int i = 2; i >= 0; i--) {
    char manufacturer_char = (manufacturer_code >> (i * 5)) & 0x1F;
    manufacturer += manufacturer_char + ('A' - 1);
  }

  model_id = edid_raw.prod_code;

  // Format of |edid_raw.serial|:
  //   32 bits, little-endian. If this field is not used, the stored value is 0.
  if (edid_raw.serial)
    serial_number = edid_raw.serial;

  // Format of |edid_raw.mfg_week|
  //   0x00: Manufacture week is not specified.
  //   0x01 - 0x36: Valid manufacture week (range is 1 to 54 weeks).
  //   0x37 - 0xFE: Reserved.
  //   0xFF: Model year flag.
  // Format of |edid_raw.mfg_year|:
  //   0x00 - 0x0F: Reserved.
  //   0x10 - 0xFF: Valid manufacture year (stored value + 1990).
  if (edid_raw.mfg_year > 0x0F && edid_raw.mfg_week != 0xFF) {
    manufacture_year = edid_raw.mfg_year + 1990;
    if (edid_raw.mfg_week < 0x37 && edid_raw.mfg_week) {
      manufacture_week = edid_raw.mfg_week;
    }
  }

  edid_version =
      base::StringPrintf("%d.%d", edid_raw.version, edid_raw.revision);

  // Format of |edid_raw.input|:
  //   Bit 7: 1 for digital input and 0 for analog input.
  //   Bits 0-6: Other input parameters.
  is_degital_input = edid_raw.input & 0x80;

  // For each display descriptor, the pixel_clock should be 0.
  // Mapping of |display_descriptor.type|:
  //   0xFC: Display name.
  for (auto display_descriptor : edid_raw.display_descriptors) {
    if (display_descriptor.pixel_clock)
      continue;
    if (display_descriptor.type == 0xFC)
      display_name = ExtractString(display_descriptor.data);
  }
}

}  // namespace diagnostics
