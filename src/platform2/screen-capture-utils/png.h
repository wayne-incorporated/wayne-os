// Copyright 2018 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef SCREEN_CAPTURE_UTILS_PNG_H_
#define SCREEN_CAPTURE_UTILS_PNG_H_

#include <stdint.h>

namespace screenshot {

// Saves a BGRX image on memory as a RGB PNG file.
void SaveAsPng(const char* path,
               void* data,
               uint32_t width,
               uint32_t height,
               uint32_t stride);

}  // namespace screenshot

#endif  // SCREEN_CAPTURE_UTILS_PNG_H_
