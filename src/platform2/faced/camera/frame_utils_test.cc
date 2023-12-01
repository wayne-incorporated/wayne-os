// Copyright 2022 The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "faced/camera/frame_utils.h"

#include <string>
#include <vector>

#include <base/strings/strcat.h>
#include <gtest/gtest.h>

namespace faced {
namespace {

// A test case where a padded image has its padding removed.
TEST(GetTightlyPackedPayload, CorrectlyRemovesPadding) {
  int height = 2;
  int width = 2;

  // Use string representations for ease of construction
  int y_stride = width + 1;
  std::string y_data_str_padded =
      "11"  // First row of data
      "a"   // Padding
      "22"  // Second row of data
      "b";  // Padding
  std::string y_data_str = "1122";
  std::vector<uint8_t> y_data(y_data_str_padded.begin(),
                              y_data_str_padded.end());

  // UV is subsampled so has half the number of rows
  int uv_stride = width + 1;
  std::string uv_data_str_padded =
      "34"  // First row of data
      "c";  // Padding
  std::string uv_data_str = "34";
  std::vector<uint8_t> uv_data(uv_data_str_padded.begin(),
                               uv_data_str_padded.end());

  // Construct planes
  cros_cam_plane_t_ plane_y{.stride = y_stride,
                            .size = static_cast<int>(y_data.size()),
                            .data = y_data.data()};
  cros_cam_plane_t_ plane_uv{.stride = uv_stride,
                             .size = static_cast<int>(uv_data.size()),
                             .data = uv_data.data()};

  std::string payload =
      GetTightlyPackedPayload(height, width, plane_y, plane_uv);
  EXPECT_EQ(payload, base::StrCat({y_data_str, uv_data_str}));
}

// A test case where an image with no padding has no change.
// stride = width
TEST(GetTightlyPackedPayload, NoChangeToPayload) {
  int height = 2;
  int width = 2;

  // Use string representations for ease of construction
  std::string y_data_str =
      "11"   // First row of data
      "22";  // Second row of data
  std::vector<uint8_t> y_data(y_data_str.begin(), y_data_str.end());

  // UV is subsampled so has half the number of rows
  std::string uv_data_str = "34";
  std::vector<uint8_t> uv_data(uv_data_str.begin(), uv_data_str.end());

  // Construct planes
  cros_cam_plane_t_ plane_y{.stride = width,
                            .size = static_cast<int>(y_data.size()),
                            .data = y_data.data()};
  cros_cam_plane_t_ plane_uv{.stride = width,
                             .size = static_cast<int>(uv_data.size()),
                             .data = uv_data.data()};

  std::string payload =
      GetTightlyPackedPayload(height, width, plane_y, plane_uv);
  EXPECT_EQ(payload, base::StrCat({y_data_str, uv_data_str}));
}

// A test case where an image with no padding has no change.
// stride = 0
TEST(GetTightlyPackedPayload, NoChangeToPayloadStrideUnused) {
  int height = 2;
  int width = 2;

  // Use string representations for ease of construction
  std::string y_data_str =
      "11"   // First row of data
      "22";  // Second row of data
  std::vector<uint8_t> y_data(y_data_str.begin(), y_data_str.end());

  // UV is subsampled so has half the number of rows
  std::string uv_data_str = "34";
  std::vector<uint8_t> uv_data(uv_data_str.begin(), uv_data_str.end());

  // Construct planes
  cros_cam_plane_t_ plane_y{.stride = 0,
                            .size = static_cast<int>(y_data.size()),
                            .data = y_data.data()};
  cros_cam_plane_t_ plane_uv{.stride = 0,
                             .size = static_cast<int>(uv_data.size()),
                             .data = uv_data.data()};

  std::string payload =
      GetTightlyPackedPayload(height, width, plane_y, plane_uv);
  EXPECT_EQ(payload, base::StrCat({y_data_str, uv_data_str}));
}

// A test case where an image with tightly packed luminance but chroma is padded
// will see the chroma data returned with padding removed
TEST(GetTightlyPackedPayload, LuminanceIsTightlyPackedChromaIsPadded) {
  int height = 2;
  int width = 2;

  // Use string representations for ease of construction
  std::string y_data_str =
      "11"   // First row of data
      "22";  // Second row of data
  std::vector<uint8_t> y_data(y_data_str.begin(), y_data_str.end());

  // UV is subsampled so has half the number of rows
  int uv_stride = width + 1;
  std::string uv_data_str_padded =
      "34"  // First row of data
      "c";  // Padding
  std::string uv_data_str = "34";
  std::vector<uint8_t> uv_data(uv_data_str_padded.begin(),
                               uv_data_str_padded.end());

  // Construct planes
  cros_cam_plane_t_ plane_y{.stride = 0,
                            .size = static_cast<int>(y_data.size()),
                            .data = y_data.data()};
  cros_cam_plane_t_ plane_uv{.stride = uv_stride,
                             .size = static_cast<int>(uv_data.size()),
                             .data = uv_data.data()};

  std::string payload =
      GetTightlyPackedPayload(height, width, plane_y, plane_uv);
  EXPECT_EQ(payload, base::StrCat({y_data_str, uv_data_str}));
}

}  // namespace
}  // namespace faced
