// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "screen-capture-utils/kmsvnc_utils.h"

namespace screenshot {

uint32_t getVncWidth(uint32_t crtc_width) {
  return (crtc_width + 3) / 4 * 4;
}

void ConvertBuffer(const DisplayBuffer::Result& from,
                   char* to,
                   uint32_t vnc_width) {
  // For cases where vnc width != display width(vnc needs to be a multiple of 4)
  // then vnc width will always be greater than display width.
  // In that case, we are copying only the available pixels from the display
  // buffer, and leaving the remainder as-is (zero valued)
  for (int i = 0; i < from.height; i++) {
    memcpy(to + vnc_width * kBytesPerPixel * i,
           static_cast<char*>(from.buffer) + from.stride * i,
           from.width * kBytesPerPixel);
  }
}

}  // namespace screenshot
