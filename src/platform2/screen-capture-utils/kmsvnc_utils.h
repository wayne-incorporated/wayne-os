// Copyright 2021 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SCREEN_CAPTURE_UTILS_KMSVNC_UTILS_H_
#define SCREEN_CAPTURE_UTILS_KMSVNC_UTILS_H_

#include <cstdint>
#include <memory>

#include "screen-capture-utils/capture.h"

namespace screenshot {

constexpr int kBytesPerPixel = 4;

uint32_t getVncWidth(uint32_t crtc_width);

void ConvertBuffer(const DisplayBuffer::Result& from,
                   char* to,
                   uint32_t vnc_width);
}  // namespace screenshot

#endif  // SCREEN_CAPTURE_UTILS_KMSVNC_UTILS_H_
