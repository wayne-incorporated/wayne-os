// Copyright 2019 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "arc/vm/libvda/gbm_util.h"

#include <cstdio>
#include <fcntl.h>
#include <utility>

#include <base/logging.h>
#include <base/notreached.h>
#include <base/posix/eintr_wrapper.h>

namespace arc {

// static
ScopedGbmDevice ScopedGbmDevice::Create() {
  // follow the implementation at:
  // https://source.corp.google.com/chromeos_public/src/platform/minigbm/cros_gralloc/cros_gralloc_driver.cc;l=90;bpv=0;cl=c06cc9cccb3cf3c7f9d2aec706c27c34cd6162a0
  constexpr int kDrmNumNodes = 63;
  constexpr int kDrmRenderNodeStart = 128;
  constexpr int kDrmCardNodeStart = 0;
  constexpr char kRenderNodesFmt[] = "/dev/dri/renderD%d";
  constexpr char kCardNodesFmt[] = "/dev/dri/card%d";

  char path[32];
  // Try render nodes...
  for (int offset = 0; offset < kDrmNumNodes; ++offset) {
    std::snprintf(path, sizeof(path), kRenderNodesFmt,
                  kDrmRenderNodeStart + offset);
    base::ScopedFD fd(HANDLE_EINTR(open(path, O_RDWR)));
    if (!fd.is_valid())
      continue;

    gbm_device* device = gbm_create_device(fd.get());
    if (device)
      return ScopedGbmDevice(device, std::move(fd));
  }

  // Try card nodes... for vkms mostly.
  for (int offset = 0; offset < kDrmNumNodes; ++offset) {
    std::snprintf(path, sizeof(path), kCardNodesFmt,
                  kDrmCardNodeStart + offset);
    base::ScopedFD fd(HANDLE_EINTR(open(path, O_RDWR)));
    if (!fd.is_valid())
      continue;

    gbm_device* device = gbm_create_device(fd.get());
    if (device)
      return ScopedGbmDevice(device, std::move(fd));
  }

  LOG(ERROR) << "Could not create gbm device.";
  return ScopedGbmDevice();
}

ScopedGbmDevice::ScopedGbmDevice(gbm_device* device, base::ScopedFD device_fd)
    : device_(device), device_fd_(std::move(device_fd)) {
  DCHECK(device_);
  DCHECK(device_fd_.get());
}

ScopedGbmDevice::~ScopedGbmDevice() {
  reset();
}

ScopedGbmDevice::ScopedGbmDevice(ScopedGbmDevice&& rvalue)
    : device_(rvalue.device_), device_fd_(std::move(rvalue.device_fd_)) {
  rvalue.device_ = nullptr;
}

ScopedGbmDevice& ScopedGbmDevice::operator=(ScopedGbmDevice&& rvalue) {
  reset();
  device_ = rvalue.device_;
  device_fd_ = std::move(rvalue.device_fd_);
  rvalue.device_ = nullptr;
  return *this;
}

gbm_device* ScopedGbmDevice::get() {
  return device_;
}

void ScopedGbmDevice::reset() {
  if (device_) {
    gbm_device_destroy(device_);
    device_ = nullptr;
  }
  device_fd_.reset();
}

uint32_t ConvertPixelFormatToGbmFormat(video_pixel_format_t format) {
  switch (format) {
    case YV12:
      return GBM_FORMAT_YVU420;
    case NV12:
      return GBM_FORMAT_NV12;
    default:
      return 0;
  }
}

std::vector<video_pixel_format_t> GetSupportedRawFormats(
    GbmUsageType usage_type) {
  auto device = ScopedGbmDevice::Create();
  if (!device.get())
    return {};

  uint32_t usage_flags = GBM_BO_USE_TEXTURING;
  switch (usage_type) {
    case ENCODE:
      usage_flags |= GBM_BO_USE_HW_VIDEO_ENCODER;
      break;
    case DECODE:
      usage_flags |= GBM_BO_USE_HW_VIDEO_DECODER;
      break;
    default:
      NOTREACHED();
  }

  std::vector<video_pixel_format_t> formats;
  constexpr video_pixel_format_t pixel_formats[] = {NV12, YV12};
  for (video_pixel_format_t pixel_format : pixel_formats) {
    // VEA has NV12 hardcoded as the only allowed format on many devices,
    // only check NV12 for now.
    if (usage_type == ENCODE && pixel_format != NV12)
      continue;

    uint32_t gbm_format = ConvertPixelFormatToGbmFormat(pixel_format);
    if (gbm_format == 0u)
      continue;
    if (!gbm_device_is_format_supported(device.get(), gbm_format,
                                        usage_flags)) {
      DLOG(INFO) << "Not supported: " << pixel_format;
      continue;
    }
    formats.push_back(pixel_format);
  }
  return formats;
}

}  // namespace arc
