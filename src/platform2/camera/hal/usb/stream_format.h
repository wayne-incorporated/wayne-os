/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_STREAM_FORMAT_H_
#define CAMERA_HAL_USB_STREAM_FORMAT_H_

#include <vector>

#include <hardware/camera3.h>

#include "hal/usb/common_types.h"

namespace cros {

// Find a resolution from a supported list.
const SupportedFormat* FindFormatByResolution(const SupportedFormats& formats,
                                              uint32_t width,
                                              uint32_t height);

// Get the largest resolution from |supported_formats|.
SupportedFormat GetMaximumFormat(const SupportedFormats& supported_formats);

// Get all supported JPEG thumbnail sizes.  See the requirements in
// https://developer.android.com/reference/android/hardware/camera2/CameraCharacteristics.html#JPEG_AVAILABLE_THUMBNAIL_SIZES
// Return flattened sizes [width_0, height_0, width_1, height_1, ...] for
// filling as camera metadata.
std::vector<int32_t> GetJpegAvailableThumbnailSizes(
    const SupportedFormats& supported_formats);

// Find all formats in preference order.
// The resolutions in returned SupportedFormats vector are unique.
SupportedFormats GetQualifiedFormats(const SupportedFormats& supported_formats,
                                     uint32_t quirks);

// Check |stream| is supported in |supported_formats|.
bool IsFormatSupported(const SupportedFormats& supported_formats,
                       const camera3_stream_t& stream);

// Get the maximum frame rate of |format|.
float GetMaximumFrameRate(const SupportedFormat& format);

}  // namespace cros

#endif  // CAMERA_HAL_USB_STREAM_FORMAT_H_
