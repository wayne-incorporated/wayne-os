/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/privacy_shutter_detector_impl.h"

#include <linux/videodev2.h>

#include <memory>

#include "cros-camera/common.h"

namespace cros {

const int kMaxThreshold = 86;
const int kMeanThreshold = 26;
const int kVarThreshold = 29;

std::unique_ptr<PrivacyShutterDetector> PrivacyShutterDetector::New() {
  return std::make_unique<PrivacyShutterDetectorImpl>();
}

PrivacyShutterDetectorImpl::PrivacyShutterDetectorImpl() = default;

PrivacyShutterDetectorImpl::~PrivacyShutterDetectorImpl() = default;

bool PrivacyShutterDetectorImpl::DetectPrivacyShutterFromHandle(
    buffer_handle_t input, bool* isShutterClosed) {
  auto mapping = ScopedMapping(input);
  if (!mapping.is_valid()) {
    LOGF(ERROR) << "Failed to map the buffer to detect privacy shutter.";
    return false;
  } else if (mapping.v4l2_format() != V4L2_PIX_FMT_NV12) {
    LOGF(ERROR) << "The input is not NV12 format.";
    return false;
  }

  *isShutterClosed = DetectPrivacyShutterFromHandleInternal(mapping);
  return true;
}

bool PrivacyShutterDetectorImpl::DetectPrivacyShutterFromHandleInternal(
    const ScopedMapping& mapping) {
  uint8_t* yData = mapping.plane(0).addr;
  uint32_t yStride = mapping.plane(0).stride;
  int width = mapping.width();
  int height = mapping.height();

  double ySum = 0;
  for (uint32_t y = 0; y < height; y++) {
    for (uint32_t x = 0; x < width; x++) {
      auto offset = yStride * y + x;
      ySum += yData[offset];
      if (kMaxThreshold < yData[offset]) {
        LOGF(INFO) << "The image has a bright spot: "
                   << static_cast<int>(yData[offset]);
        return false;
      }
    }
  }

  double yMean = ySum / width / height;
  if (kMeanThreshold < yMean) {
    LOGF(INFO) << "The image is overall bright: " << yMean;
    return false;
  }

  int64_t yVar = 0;
  for (uint32_t y = 0; y < height; y++) {
    for (uint32_t x = 0; x < width; x++) {
      auto offset = yStride * y + x;
      yVar += pow(yData[offset] - yMean, 2);
    }
  }

  yVar /= width * height;
  if (kVarThreshold < yVar) {
    LOGF(INFO) << "Variance is over threshold: " << yVar;
    return false;
  }

  return true;
}

}  // namespace cros
