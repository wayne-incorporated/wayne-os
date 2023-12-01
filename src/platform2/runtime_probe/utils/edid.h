// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef RUNTIME_PROBE_UTILS_EDID_H_
#define RUNTIME_PROBE_UTILS_EDID_H_

#include <memory>
#include <string>
#include <vector>

namespace runtime_probe {

// Simplified edid structure refer to:
// https://elixir.bootlin.com/linux/latest/source/include/drm/drm_edid.h
struct EdidRaw {
  uint8_t header[8];
  uint8_t mfg_id[2];
  uint8_t prod_code[2];
  uint8_t pad_1[6];  // 12 - 17
  uint8_t version;
  uint8_t pad_2[35];  // 19 - 53;
  uint16_t pixel_clock;
  uint8_t hactive_lo;
  uint8_t hblank_lo;
  uint8_t hactive_hblank_hi;
  uint8_t vactive_lo;
  uint8_t vblank_lo;
  uint8_t vactive_vblank_hi;
  uint8_t pad_3[65];  // 62 - 126
  uint8_t checksum;
} __attribute__((packed));

struct Edid {
  std::string vendor;
  int product_id;
  int width;
  int height;

  static std::unique_ptr<Edid> From(const std::vector<uint8_t>& blob);
};

}  // namespace runtime_probe

#endif  // RUNTIME_PROBE_UTILS_EDID_H_
