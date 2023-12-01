/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "cros-camera/camera_face_detection.h"

#include <optional>

#include <base/at_exit.h>
#include <gtest/gtest.h>

namespace cros {

TEST(FaceDetector, GetCoordinateTransformTest) {
  {
    Size src{1280, 720};
    Size dst{1920, 1080};

    std::optional<std::tuple<float, float, float>> transform =
        FaceDetector::GetCoordinateTransform(src, dst);

    const float scale = std::get<0>(*transform);
    const float offset_x = std::get<1>(*transform);
    const float offset_y = std::get<2>(*transform);

    ASSERT_TRUE(transform.has_value());
    ASSERT_EQ(scale, 1.5f);
    ASSERT_EQ(offset_x, 0);
    ASSERT_EQ(offset_y, 0);
  }
  {
    Size src{1280, 720};
    Size dst{2560, 1920};

    std::optional<std::tuple<float, float, float>> transform =
        FaceDetector::GetCoordinateTransform(src, dst);

    const float scale = std::get<0>(*transform);
    const float offset_x = std::get<1>(*transform);
    const float offset_y = std::get<2>(*transform);

    ASSERT_TRUE(transform.has_value());
    ASSERT_EQ(scale, 2.0f);
    ASSERT_EQ(offset_x, 0);
    ASSERT_EQ(offset_y, 240.0f);
  }
  {
    Size src{640, 480};
    Size dst{1920, 1080};

    std::optional<std::tuple<float, float, float>> transform =
        FaceDetector::GetCoordinateTransform(src, dst);

    const float scale = std::get<0>(*transform);
    const float offset_x = std::get<1>(*transform);
    const float offset_y = std::get<2>(*transform);

    ASSERT_TRUE(transform.has_value());
    ASSERT_EQ(scale, 2.25f);
    ASSERT_EQ(offset_x, 240.0f);
    ASSERT_EQ(offset_y, 0);
  }
  {
    Size src{640, 360};
    Size dst{640, 480};

    std::optional<std::tuple<float, float, float>> transform =
        FaceDetector::GetCoordinateTransform(src, dst);

    const float scale = std::get<0>(*transform);
    const float offset_x = std::get<1>(*transform);
    const float offset_y = std::get<2>(*transform);

    ASSERT_TRUE(transform.has_value());
    ASSERT_EQ(scale, 1.0f);
    ASSERT_EQ(offset_x, 0);
    ASSERT_EQ(offset_y, 60.0f);
  }
  {
    Size src{960, 720};
    Size dst{1280, 720};

    std::optional<std::tuple<float, float, float>> transform =
        FaceDetector::GetCoordinateTransform(src, dst);

    const float scale = std::get<0>(*transform);
    const float offset_x = std::get<1>(*transform);
    const float offset_y = std::get<2>(*transform);

    ASSERT_TRUE(transform.has_value());
    ASSERT_EQ(scale, 1.0f);
    ASSERT_EQ(offset_x, 160.0f);
    ASSERT_EQ(offset_y, 0);
  }
  {
    Size src{1600, 1200};
    Size dst{1920, 1080};

    std::optional<std::tuple<float, float, float>> transform =
        FaceDetector::GetCoordinateTransform(src, dst);

    ASSERT_FALSE(transform.has_value());
  }
}

}  // namespace cros

int main(int argc, char** argv) {
  base::AtExitManager exit_manager;
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
