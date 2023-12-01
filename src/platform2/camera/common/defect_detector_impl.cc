/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/defect_detector_impl.h"

#include <linux/videodev2.h>

#include <memory>

#include "cros-camera/common.h"

namespace cros {

std::unique_ptr<DefectDetector> DefectDetector::New() {
  return std::make_unique<DefectDetectorImpl>();
}

DefectDetectorImpl::DefectDetectorImpl() = default;

DefectDetectorImpl::~DefectDetectorImpl() = default;

bool DefectDetectorImpl::DetectDefectiveLineFromHandle(buffer_handle_t input,
                                                       bool* isLineFound) {
  auto mapping = ScopedMapping(input);
  if (!mapping.is_valid()) {
    LOGF(ERROR) << "Failed to map the buffer to detect a defective line.";
    return false;
  } else if (mapping.v4l2_format() != V4L2_PIX_FMT_NV12) {
    LOGF(ERROR) << "The input is not NV12 format.";
    return false;
  }

  *isLineFound = DetectDefectiveLineFromHandleInternal(mapping);
  return true;
}

bool DefectDetectorImpl::DetectDefectiveLineFromHandleInternal(
    const ScopedMapping& mapping) {
  uint8_t* cbData = mapping.plane(1).addr;
  uint8_t* crData = mapping.plane(1).addr + 1;
  size_t cStride = mapping.plane(1).stride;
  size_t chroma_step = 2;
  int width = mapping.width();
  int height = mapping.height();

  // Detect Horizontal Defective Line
  for (uint32_t y = 0; y < height / 2; y++) {
    auto offset = cStride * y;
    if (cbData[offset] != crData[offset]) {
      continue;
    }
    int initialValue = cbData[offset];
    if (initialValue > 0 && initialValue < 255) {
      continue;
    }
    bool isValueSame = true;
    for (uint32_t x = 1; x < width / 2; x++) {
      offset += chroma_step;
      if (cbData[offset] != initialValue || crData[offset] != initialValue) {
        isValueSame = false;
        break;
      }
    }
    if (isValueSame) {
      LOGF(INFO) << "There is a horizontal defective line with a value of "
                 << initialValue;
      return true;
    }
  }

  // Detect Vertical Defective Line
  for (uint32_t x = 0; x < width / 2; x++) {
    auto offset = x * chroma_step;
    if (cbData[offset] != crData[offset]) {
      continue;
    }
    int initialValue = cbData[offset];
    if (initialValue > 0 && initialValue < 255) {
      continue;
    }
    bool isValueSame = true;
    for (uint32_t y = 1; y < height / 2; y++) {
      offset += cStride;
      if (cbData[offset] != initialValue || crData[offset] != initialValue) {
        isValueSame = false;
        break;
      }
    }
    if (isValueSame) {
      LOGF(INFO) << "There is a vertical defective line with a value of "
                 << initialValue;
      return true;
    }
  }

  return false;
}

}  // namespace cros
