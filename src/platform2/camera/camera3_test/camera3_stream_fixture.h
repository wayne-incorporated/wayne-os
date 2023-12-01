// Copyright 2016 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CAMERA_CAMERA3_TEST_CAMERA3_STREAM_FIXTURE_H_
#define CAMERA_CAMERA3_TEST_CAMERA3_STREAM_FIXTURE_H_

#include <unordered_map>

#include <gtest/gtest.h>
#include <hardware/camera3.h>
#include <hardware/hardware.h>

#include "camera3_test/camera3_device_fixture.h"

namespace camera3_test {

class Camera3StreamFixture : public Camera3DeviceFixture {
 public:
  explicit Camera3StreamFixture(int32_t cam_id)
      : Camera3DeviceFixture(cam_id), cam_id_(cam_id) {}
  Camera3StreamFixture(const Camera3StreamFixture&) = delete;
  Camera3StreamFixture& operator=(const Camera3StreamFixture&) = delete;

  void SetUp() override;

  void TearDown() override;

  // Select minimal size by number of pixels.
  int32_t GetMinResolution(int32_t format,
                           ResolutionInfo* resolution,
                           bool is_output);

  // Select maximal size by number of pixels.
  int32_t GetMaxResolution(int32_t format,
                           ResolutionInfo* resolution,
                           bool is_output);

  // Get resolution under limit
  ResolutionInfo CapResolution(ResolutionInfo input,
                               ResolutionInfo limit) const;

 protected:
  const int32_t cam_id_;

  int32_t default_format_ = HAL_PIXEL_FORMAT_YCbCr_420_888;

  int32_t default_width_ = 640;

  int32_t default_height_ = 480;
};

}  // namespace camera3_test

#endif  // CAMERA_CAMERA3_TEST_CAMERA3_STREAM_FIXTURE_H_
