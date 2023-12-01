// Copyright 2020 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef LIBEC_FINGERPRINT_SENSOR_IMAGE_H_
#define LIBEC_FINGERPRINT_SENSOR_IMAGE_H_

#include <cstdint>

struct SensorImage {
  SensorImage(int width,
              int height,
              uint32_t frame_size,
              uint32_t pixel_format,
              uint16_t bpp)
      : width(width),
        height(height),
        frame_size(frame_size),
        pixel_format(pixel_format),
        bpp(bpp) {}

  int width = 0;
  int height = 0;
  uint32_t frame_size = 0;
  uint32_t pixel_format = 0;
  uint16_t bpp = 0;
};

#endif  // LIBEC_FINGERPRINT_SENSOR_IMAGE_H_
