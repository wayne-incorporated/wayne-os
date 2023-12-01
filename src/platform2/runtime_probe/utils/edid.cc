// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <numeric>

#include <base/logging.h>

#include "runtime_probe/utils/edid.h"

namespace {
constexpr int kSize = sizeof(runtime_probe::EdidRaw);
constexpr int kVersion = 0x01;
constexpr uint8_t kMagic[] = "\x00\xff\xff\xff\xff\xff\xff\x00";
constexpr int kMagicLen = 8;
constexpr int kManufacturerIdBits = 5;
}  // namespace

namespace runtime_probe {

std::unique_ptr<Edid> Edid::From(const std::vector<uint8_t>& blob) {
  auto edid = std::make_unique<Edid>();

  if (blob.size() < kSize) {
    LOG(ERROR) << "Edid::From: length too small. (" << blob.size() << ")";
    return nullptr;
  }

  EdidRaw edid_raw;
  std::copy(blob.begin(), blob.begin() + kSize,
            reinterpret_cast<uint8_t*>(&edid_raw));

  if (!std::equal(kMagic, kMagic + kMagicLen, edid_raw.header)) {
    LOG(ERROR) << "Edid::From: incorrect header.";
    return nullptr;
  }
  if (edid_raw.version != kVersion) {
    LOG(ERROR) << "Edid::From: unsupported EDID version.";
    return nullptr;
  }
  if ((std::accumulate(blob.begin(), blob.begin() + kSize, 0) & 0xff) != 0) {
    LOG(ERROR) << "Edid::From: checksum error.";
    return nullptr;
  }
  if (!edid_raw.pixel_clock) {
    LOG(ERROR) << "Edid::From: non-pixel clock format is not supported yet.";
    return nullptr;
  }

  int vendor_code = (edid_raw.mfg_id[0] << 8) | edid_raw.mfg_id[1];
  edid->product_id = (edid_raw.prod_code[1] << 8) | edid_raw.prod_code[0];
  edid->width = ((edid_raw.hactive_hblank_hi >> 4) << 8) | edid_raw.hactive_lo;
  edid->height = ((edid_raw.vactive_vblank_hi >> 4) << 8) | edid_raw.vactive_lo;
  edid->vendor = "";
  for (int i = 2; i >= 0; i--) {
    char vendor_char = (vendor_code >> (i * kManufacturerIdBits)) & 0x1f;
    edid->vendor += vendor_char + 'A' - 1;
  }
  return edid;
}

}  // namespace runtime_probe
