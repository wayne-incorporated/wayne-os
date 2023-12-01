// Copyright 2023 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_EDID_H_
#define DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_EDID_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <vector>

namespace diagnostics {

struct EdidInfo {
  std::string manufacturer;
  uint16_t model_id;
  std::optional<uint32_t> serial_number;
  std::optional<uint8_t> manufacture_week;
  std::optional<uint16_t> manufacture_year;
  std::string edid_version;
  bool is_degital_input;
  std::optional<std::string> display_name;
};

// Simplified edid structure refer to:
// https://elixir.bootlin.com/linux/latest/source/include/drm/drm_edid.h
struct DisplayDescriptor {
  uint16_t pixel_clock;
  uint8_t pad1;
  uint8_t type;
  uint8_t pad2;
  uint8_t data[13];
} __attribute__((packed));

struct EdidRaw {
  uint8_t header[8];
  uint8_t mfg_id[2];
  uint16_t prod_code;
  uint32_t serial;
  uint8_t mfg_week;
  uint8_t mfg_year;
  uint8_t version;
  uint8_t revision;
  uint8_t input;
  uint8_t pad_1[33];  // 21 - 54;
  uint16_t pixel_clock;
  uint8_t pad_2[16];  // 56 - 71
  struct DisplayDescriptor display_descriptors[3];
  uint8_t num_extensions;
  uint8_t checksum;
} __attribute__((packed));

class Edid : public EdidInfo {
 public:
  static std::optional<EdidInfo> From(const std::vector<uint8_t>& blob);
  Edid(const Edid&) = delete;
  Edid& operator=(const Edid&) = delete;
  ~Edid() = default;

 private:
  explicit Edid(const EdidRaw& edid_raw);
};

}  // namespace diagnostics

#endif  // DIAGNOSTICS_CROS_HEALTHD_DELEGATE_UTILS_EDID_H_
