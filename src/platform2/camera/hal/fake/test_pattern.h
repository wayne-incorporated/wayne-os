/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_TEST_PATTERN_H_
#define CAMERA_HAL_FAKE_TEST_PATTERN_H_

#include <memory>
#include <optional>

#include <camera/camera_metadata.h>

#include "cros-camera/common_types.h"
#include "hal/fake/frame_buffer/gralloc_frame_buffer.h"

namespace cros {

std::unique_ptr<GrallocFrameBuffer> GenerateTestPattern(
    Size size, camera_metadata_enum_android_sensor_test_pattern_mode mode);

}  // namespace cros

#endif  // CAMERA_HAL_FAKE_TEST_PATTERN_H_
