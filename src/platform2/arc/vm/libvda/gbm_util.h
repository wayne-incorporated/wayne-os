// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ARC_VM_LIBVDA_GBM_UTIL_H_
#define ARC_VM_LIBVDA_GBM_UTIL_H_

#include <stdint.h>

#include <memory>
#include <vector>

#include <base/files/scoped_file.h>
#include <gbm.h>

#include "arc/vm/libvda/libvda_common.h"

namespace arc {

// Owns the gdm_device and its underlying file descriptor.
class ScopedGbmDevice {
 public:
  // Creates the GBM device by searching the default path for renderer node.
  static ScopedGbmDevice Create();

  ScopedGbmDevice() = default;
  ~ScopedGbmDevice();

  ScopedGbmDevice(ScopedGbmDevice&& rvalue);
  ScopedGbmDevice& operator=(ScopedGbmDevice&& rvalue);
  ScopedGbmDevice(const ScopedGbmDevice&) = delete;
  ScopedGbmDevice& operator=(const ScopedGbmDevice&) = delete;

  gbm_device* get();
  void reset();

 private:
  ScopedGbmDevice(gbm_device* device, base::ScopedFD device_fd);

  gbm_device* device_ = nullptr;
  base::ScopedFD device_fd_;
};

struct GbmBoDeleter {
  void operator()(gbm_bo* bo) { gbm_bo_destroy(bo); }
};
using ScopedGbmBoPtr = std::unique_ptr<gbm_bo, GbmBoDeleter>;

// Converts from libvda's pixel format to GBM format.
uint32_t ConvertPixelFormatToGbmFormat(video_pixel_format_t format);

enum GbmUsageType { DECODE, ENCODE };

// Returns a list of supported raw formats. When |encode| is true, it will
// check for formats suitable for encoding, else for decoding.
std::vector<video_pixel_format_t> GetSupportedRawFormats(
    GbmUsageType usage_type);

}  // namespace arc

#endif  // ARC_VM_LIBVDA_GBM_UTIL_H_
