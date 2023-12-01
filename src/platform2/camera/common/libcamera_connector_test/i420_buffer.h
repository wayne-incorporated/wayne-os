/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_LIBCAMERA_CONNECTOR_TEST_I420_BUFFER_H_
#define CAMERA_COMMON_LIBCAMERA_CONNECTOR_TEST_I420_BUFFER_H_

#include <string>
#include <vector>

#include <gtest/gtest.h>
#include <linux/videodev2.h>
#include <libyuv.h>

#include "common/libcamera_connector_test/util.h"
#include "cros-camera/camera_service_connector.h"

namespace cros {
namespace tests {

class I420Buffer {
 public:
  explicit I420Buffer(int width = 0, int height = 0)
      : width_(width), height_(height), data_(DataSize()) {}

  static I420Buffer Create(const cros_cam_frame_t* frame) {
    const cros_cam_format_info_t& format = frame->format;
    I420Buffer buf(format.width, format.height);

    const cros_cam_plane_t* planes = frame->planes;

    auto expect_empty = [&](const cros_cam_plane_t& plane) {
      EXPECT_EQ(plane.size, 0);
      EXPECT_EQ(plane.stride, 0);
      EXPECT_EQ(plane.data, nullptr);
    };

    switch (format.fourcc) {
      case V4L2_PIX_FMT_NV12: {
        expect_empty(planes[2]);
        expect_empty(planes[3]);
        int ret = libyuv::NV12ToI420(
            planes[0].data, planes[0].stride, planes[1].data, planes[1].stride,
            buf.DataY(), buf.StrideY(), buf.DataU(), buf.StrideU(), buf.DataY(),
            buf.StrideV(), buf.Width(), buf.Height());
        EXPECT_EQ(ret, 0) << "invalid NV12 frame";
        break;
      }
      case V4L2_PIX_FMT_MJPEG: {
        expect_empty(planes[1]);
        expect_empty(planes[2]);
        expect_empty(planes[3]);
        int ret = libyuv::MJPGToI420(
            planes[0].data, planes[0].size, buf.DataY(), buf.StrideY(),
            buf.DataU(), buf.StrideU(), buf.DataV(), buf.StrideV(),
            format.width, format.height, buf.Width(), buf.Height());
        EXPECT_EQ(ret, 0) << "invalid MJPEG frame";
        break;
      }
      default:
        ADD_FAILURE() << "unexpected fourcc: " << FourccToString(format.fourcc);
    }
    return buf;
  }

  int Width() const { return width_; }
  int Height() const { return height_; }

  int StrideY() const { return width_; }
  int StrideU() const { return (width_ + 1) / 2; }
  int StrideV() const { return (width_ + 1) / 2; }

  uint8_t* DataY() { return data_.data(); }
  uint8_t* DataU() { return DataY() + StrideY() * Height(); }
  uint8_t* DataV() { return DataU() + StrideU() * HalfHeight(); }

 private:
  int HalfHeight() const { return (height_ + 1) / 2; }
  int HalfWidth() const { return (width_ + 1) / 2; }
  int DataSize() const {
    return StrideY() * Height() + (StrideU() + StrideV()) * HalfHeight();
  }

  int width_;
  int height_;
  std::vector<uint8_t> data_;
};

}  // namespace tests
}  // namespace cros

#endif  // CAMERA_COMMON_LIBCAMERA_CONNECTOR_TEST_I420_BUFFER_H_
