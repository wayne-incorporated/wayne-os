/* Copyright 2017 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/image_processor.h"

#include <errno.h>
#include <libyuv.h>
#include <time.h>

#include <base/memory/ptr_util.h>

#include "cros-camera/common.h"
#include "hal/usb/common_types.h"

namespace cros {

/*
 * Formats have different names in different header files. Here is the mapping
 * table:
 *
 * android_pixel_format_t           videodev2.h            FOURCC in libyuv
 * -----------------------------------------------------------------------------
 * HAL_PIXEL_FORMAT_RGBA_8888     = V4L2_PIX_FMT_RGBX32  = FOURCC_ABGR
 * HAL_PIXEL_FORMAT_YCbCr_422_I   = V4L2_PIX_FMT_YUYV    = FOURCC_YUYV
 *                                                       = FOURCC_YUY2
 *                                  V4L2_PIX_FMT_YUV420  = FOURCC_I420
 *                                                       = FOURCC_YU12
 *                                  V4L2_PIX_FMT_MJPEG   = FOURCC_MJPG
 *
 * HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED and HAL_PIXEL_FORMAT_YCbCr_420_888
 * may be backed by different types of buffers depending on the platform.
 *
 * HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED
 *                                = V4L2_PIX_FMT_NV12    = FOURCC_NV12
 *                                = V4L2_PIX_FMT_RGBX32  = FOURCC_ABGR
 *
 * HAL_PIXEL_FORMAT_YCbCr_420_888 = V4L2_PIX_FMT_NV12    = FOURCC_NV12
 *                                = V4L2_PIX_FMT_YVU420  = FOURCC_YV12
 *
 * Camera device generates FOURCC_YUYV and FOURCC_MJPG.
 * At the Android side:
 * - Camera preview uses HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED buffers.
 * - Video recording uses HAL_PIXEL_FORMAT_YCbCr_420_888 buffers.
 * - Still capture uses HAL_PIXEL_FORMAT_BLOB buffers.
 * - CTS requires FOURCC_YV12 and FOURCC_NV21 for applications.
 *
 * Android stride requirement:
 * YV12 horizontal stride should be a multiple of 16 pixels. See
 * android.graphics.ImageFormat.YV12.
 * The stride of ARGB, YU12, and NV21 are always equal to the width.
 *
 * Conversion Path:
 * MJPG/YUYV (from camera) -> YU12 -> ARGB / NM12 (preview)
 *                                 -> NV21 (apps)
 *                                 -> YV12 (apps)
 *                                 -> NM12 / YV12 (video encoder)
 */

size_t ImageProcessor::GetConvertedSize(FrameBuffer& frame) {
  if (frame.Map()) {
    LOGF(ERROR) << "Failed to map frame";
    return 0;
  }
  if ((frame.GetWidth() % 2) || (frame.GetHeight() % 2)) {
    LOGF(ERROR) << "Width or height is not even (" << frame.GetWidth() << " x "
                << frame.GetHeight() << ")";
    return 0;
  }

  switch (frame.GetFourcc()) {
    case V4L2_PIX_FMT_YVU420:
    case V4L2_PIX_FMT_YVU420M:  // YM21, multiple planes YV12
    case V4L2_PIX_FMT_YUV420:
    case V4L2_PIX_FMT_YUV420M:  // YM12, multiple planes YU12
      if (frame.GetNumPlanes() != 3) {
        LOGF(ERROR) << "Stride is not set correctly";
        return 0;
      }
      return frame.GetStride(FrameBuffer::YPLANE) * frame.GetHeight() +
             frame.GetStride(FrameBuffer::UPLANE) * frame.GetHeight() / 2 +
             frame.GetStride(FrameBuffer::VPLANE) * frame.GetHeight() / 2;
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M:  // NV12, multiple planes
      if (frame.GetNumPlanes() != 2) {
        LOGF(ERROR) << "Stride is not set correctly";
        return 0;
      }
      return frame.GetStride(FrameBuffer::YPLANE) * frame.GetHeight() +
             frame.GetStride(FrameBuffer::UPLANE) * frame.GetHeight() / 2;
    case V4L2_PIX_FMT_YUYV:
    case V4L2_PIX_FMT_RGBX32:
    case V4L2_PIX_FMT_RGB24:
      return frame.GetStride() * frame.GetHeight();
    case V4L2_PIX_FMT_INVZ:
    case V4L2_PIX_FMT_Y16:
    case V4L2_PIX_FMT_Z16:
      return 2 * frame.GetStride() * frame.GetHeight();
    default:
      LOGF(ERROR) << "Pixel format " << FormatToString(frame.GetFourcc())
                  << " is unsupported.";
      return 0;
  }
}

int ImageProcessor::ConvertFormat(FrameBuffer& in_frame,
                                  FrameBuffer& out_frame) {
  if (in_frame.Map() || out_frame.Map()) {
    LOGF(ERROR) << "Failed to map frame";
    return -EINVAL;
  }
  if ((in_frame.GetWidth() % 2) || (in_frame.GetHeight() % 2)) {
    LOGF(ERROR) << "Width or height is not even (" << in_frame.GetWidth()
                << " x " << in_frame.GetHeight() << ")";
    return -EINVAL;
  }

  VLOGF(1) << "Convert format from " << FormatToString(in_frame.GetFourcc())
           << " to " << FormatToString(out_frame.GetFourcc());

  if (in_frame.GetFourcc() == V4L2_PIX_FMT_YUYV) {
    switch (out_frame.GetFourcc()) {
      case V4L2_PIX_FMT_YUV420:     // YU12
      case V4L2_PIX_FMT_YUV420M:    // YM12, multiple planes YU12
      case V4L2_PIX_FMT_YVU420:     // YV12
      case V4L2_PIX_FMT_YVU420M: {  // YM21, multiple planes YV12
        int res =
            libyuv::YUY2ToI420(in_frame.GetData(), in_frame.GetStride(),
                               out_frame.GetData(FrameBuffer::YPLANE),
                               out_frame.GetStride(FrameBuffer::YPLANE),
                               out_frame.GetData(FrameBuffer::UPLANE),
                               out_frame.GetStride(FrameBuffer::UPLANE),
                               out_frame.GetData(FrameBuffer::VPLANE),
                               out_frame.GetStride(FrameBuffer::VPLANE),
                               out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "YUY2ToI420() returns " << res;
        return res ? -EINVAL : 0;
      }
      case V4L2_PIX_FMT_NV12:     // NV12
      case V4L2_PIX_FMT_NV12M: {  // NM12
        int res =
            libyuv::YUY2ToNV12(in_frame.GetData(), in_frame.GetStride(),
                               out_frame.GetData(FrameBuffer::YPLANE),
                               out_frame.GetStride(FrameBuffer::YPLANE),
                               out_frame.GetData(FrameBuffer::UPLANE),
                               out_frame.GetStride(FrameBuffer::UPLANE),
                               out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "YUY2ToNV12() returns " << res;
        return res ? -EINVAL : 0;
      }
      default:
        LOGF(ERROR) << "Destination pixel format "
                    << FormatToString(out_frame.GetFourcc())
                    << " is unsupported for YUYV source format.";
        return -EINVAL;
    }
  } else if (in_frame.GetFourcc() == V4L2_PIX_FMT_YUV420 ||
             in_frame.GetFourcc() == V4L2_PIX_FMT_YUV420M) {
    // V4L2_PIX_FMT_YVU420 is YV12. I420 is usually referred to YU12
    // (V4L2_PIX_FMT_YUV420), and YV12 is similar to YU12 except that U/V
    // planes are swapped.
    switch (out_frame.GetFourcc()) {
      case V4L2_PIX_FMT_YUV420:     // YU12
      case V4L2_PIX_FMT_YUV420M:    // YM12, multiple planes YU12
      case V4L2_PIX_FMT_YVU420:     // YV12
      case V4L2_PIX_FMT_YVU420M: {  // YM21, multiple planes YV12
        int res = libyuv::I420Copy(in_frame.GetData(FrameBuffer::YPLANE),
                                   in_frame.GetStride(FrameBuffer::YPLANE),
                                   in_frame.GetData(FrameBuffer::UPLANE),
                                   in_frame.GetStride(FrameBuffer::UPLANE),
                                   in_frame.GetData(FrameBuffer::VPLANE),
                                   in_frame.GetStride(FrameBuffer::VPLANE),
                                   out_frame.GetData(FrameBuffer::YPLANE),
                                   out_frame.GetStride(FrameBuffer::YPLANE),
                                   out_frame.GetData(FrameBuffer::UPLANE),
                                   out_frame.GetStride(FrameBuffer::UPLANE),
                                   out_frame.GetData(FrameBuffer::VPLANE),
                                   out_frame.GetStride(FrameBuffer::VPLANE),
                                   out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "I420Copy() returns " << res;
        return res ? -EINVAL : 0;
      }
      case V4L2_PIX_FMT_NV12:     // NV12
      case V4L2_PIX_FMT_NV12M: {  // NM12
        int res =
            libyuv::I420ToNV12(in_frame.GetData(FrameBuffer::YPLANE),
                               in_frame.GetStride(FrameBuffer::YPLANE),
                               in_frame.GetData(FrameBuffer::UPLANE),
                               in_frame.GetStride(FrameBuffer::UPLANE),
                               in_frame.GetData(FrameBuffer::VPLANE),
                               in_frame.GetStride(FrameBuffer::VPLANE),
                               out_frame.GetData(FrameBuffer::YPLANE),
                               out_frame.GetStride(FrameBuffer::YPLANE),
                               out_frame.GetData(FrameBuffer::UPLANE),
                               out_frame.GetStride(FrameBuffer::UPLANE),
                               out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "I420ToNV12() returns " << res;
        return res ? -EINVAL : 0;
      }
      case V4L2_PIX_FMT_RGBX32: {
        int res = libyuv::I420ToABGR(
            in_frame.GetData(FrameBuffer::YPLANE),
            in_frame.GetStride(FrameBuffer::YPLANE),
            in_frame.GetData(FrameBuffer::UPLANE),
            in_frame.GetStride(FrameBuffer::UPLANE),
            in_frame.GetData(FrameBuffer::VPLANE),
            in_frame.GetStride(FrameBuffer::VPLANE), out_frame.GetData(),
            out_frame.GetStride(), out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "I420ToABGR() returns " << res;
        return res ? -EINVAL : 0;
      }
      default:
        LOGF(ERROR) << "Destination pixel format "
                    << FormatToString(out_frame.GetFourcc())
                    << " is unsupported for YU12 source format.";
        return -EINVAL;
    }
  } else if (in_frame.GetFourcc() == V4L2_PIX_FMT_NV12 ||
             in_frame.GetFourcc() == V4L2_PIX_FMT_NV12M) {
    switch (out_frame.GetFourcc()) {
      case V4L2_PIX_FMT_YUV420:     // YU12
      case V4L2_PIX_FMT_YUV420M:    // YM12, multiple planes YU12
      case V4L2_PIX_FMT_YVU420:     // YV12
      case V4L2_PIX_FMT_YVU420M: {  // YM21, multiple planes YV12
        int res =
            libyuv::NV12ToI420(in_frame.GetData(FrameBuffer::YPLANE),
                               in_frame.GetStride(FrameBuffer::YPLANE),
                               in_frame.GetData(FrameBuffer::UPLANE),
                               in_frame.GetStride(FrameBuffer::UPLANE),
                               out_frame.GetData(FrameBuffer::YPLANE),
                               out_frame.GetStride(FrameBuffer::YPLANE),
                               out_frame.GetData(FrameBuffer::UPLANE),
                               out_frame.GetStride(FrameBuffer::UPLANE),
                               out_frame.GetData(FrameBuffer::VPLANE),
                               out_frame.GetStride(FrameBuffer::VPLANE),
                               out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "NV12ToI420() returns " << res;
        return res ? -EINVAL : 0;
      }
      case V4L2_PIX_FMT_NV12:     // NV12
      case V4L2_PIX_FMT_NV12M: {  // NM12
        int res = libyuv::NV12Copy(in_frame.GetData(FrameBuffer::YPLANE),
                                   in_frame.GetStride(FrameBuffer::YPLANE),
                                   in_frame.GetData(FrameBuffer::UPLANE),
                                   in_frame.GetStride(FrameBuffer::UPLANE),
                                   out_frame.GetData(FrameBuffer::YPLANE),
                                   out_frame.GetStride(FrameBuffer::YPLANE),
                                   out_frame.GetData(FrameBuffer::UPLANE),
                                   out_frame.GetStride(FrameBuffer::UPLANE),
                                   out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "NV12Copy() returns " << res;
        return res ? -EINVAL : 0;
      }
      case V4L2_PIX_FMT_RGBX32: {
        int res = libyuv::NV12ToABGR(
            in_frame.GetData(FrameBuffer::YPLANE),
            in_frame.GetStride(FrameBuffer::YPLANE),
            in_frame.GetData(FrameBuffer::UPLANE),
            in_frame.GetStride(FrameBuffer::UPLANE), out_frame.GetData(),
            out_frame.GetStride(), out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "NV12ToABGR() returns " << res;
        return res ? -EINVAL : 0;
      }
      default:
        LOGF(ERROR) << "Destination pixel format "
                    << FormatToString(out_frame.GetFourcc())
                    << " is unsupported for NV12 source format.";
        return -EINVAL;
    }
  } else if (in_frame.GetFourcc() == V4L2_PIX_FMT_JPEG ||
             in_frame.GetFourcc() == V4L2_PIX_FMT_MJPEG) {
    switch (out_frame.GetFourcc()) {
      case V4L2_PIX_FMT_YUV420:     // YU12
      case V4L2_PIX_FMT_YUV420M: {  // YM12, multiple planes YU12
        int res = libyuv::MJPGToI420(
            in_frame.GetData(), in_frame.GetDataSize(),
            out_frame.GetData(FrameBuffer::YPLANE),
            out_frame.GetStride(FrameBuffer::YPLANE),
            out_frame.GetData(FrameBuffer::UPLANE),
            out_frame.GetStride(FrameBuffer::UPLANE),
            out_frame.GetData(FrameBuffer::VPLANE),
            out_frame.GetStride(FrameBuffer::VPLANE), in_frame.GetWidth(),
            in_frame.GetHeight(), out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "libyuv::MJPEGToI420() returns " << res;
        return res ? -EINVAL : 0;
      }
      case V4L2_PIX_FMT_NV12:     // NV12
      case V4L2_PIX_FMT_NV12M: {  // NM12
        int res = libyuv::MJPGToNV12(
            in_frame.GetData(), in_frame.GetDataSize(),
            out_frame.GetData(FrameBuffer::YPLANE),
            out_frame.GetStride(FrameBuffer::YPLANE),
            out_frame.GetData(FrameBuffer::UPLANE),
            out_frame.GetStride(FrameBuffer::UPLANE), in_frame.GetWidth(),
            in_frame.GetHeight(), out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "libyuv::MJPGToNV12() returns " << res;
        return res ? -EINVAL : 0;
      }
      default:
        LOGF(ERROR) << "Destination pixel format "
                    << FormatToString(out_frame.GetFourcc())
                    << " is unsupported for MJPEG source format.";
        return -EINVAL;
    }
  } else if (in_frame.GetFourcc() == V4L2_PIX_FMT_RGB24) {
    switch (out_frame.GetFourcc()) {
      case V4L2_PIX_FMT_YUV420:     // YU12
      case V4L2_PIX_FMT_YUV420M:    // YM12, multiple planes YU12
      case V4L2_PIX_FMT_YVU420:     // YV12
      case V4L2_PIX_FMT_YVU420M: {  // YM21, multiple planes YV12
        int res =
            libyuv::RGB24ToI420(in_frame.GetData(), in_frame.GetStride(),
                                out_frame.GetData(FrameBuffer::YPLANE),
                                out_frame.GetStride(FrameBuffer::YPLANE),
                                out_frame.GetData(FrameBuffer::UPLANE),
                                out_frame.GetStride(FrameBuffer::UPLANE),
                                out_frame.GetData(FrameBuffer::VPLANE),
                                out_frame.GetStride(FrameBuffer::VPLANE),
                                out_frame.GetWidth(), out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "RGB24ToI420() returns " << res;
        return res ? -EINVAL : 0;
      }
      case V4L2_PIX_FMT_NV12:     // NV12
      case V4L2_PIX_FMT_NV12M: {  // NM12
        if (!SharedFrameBuffer::Reallocate(
                in_frame.GetWidth(), in_frame.GetHeight(), V4L2_PIX_FMT_YUV420,
                &temp_i420_buffer_)) {
          return -EINVAL;
        }
        // TODO(b/151201659): Currently we convert RGB24 to I420 and then
        // convert I420 to NV12. We should find a way to convert it directly
        // if the performance is not acceptable.
        int res = libyuv::RGB24ToI420(
            in_frame.GetData(), in_frame.GetStride(),
            temp_i420_buffer_->GetData(FrameBuffer::YPLANE),
            temp_i420_buffer_->GetStride(FrameBuffer::YPLANE),
            temp_i420_buffer_->GetData(FrameBuffer::UPLANE),
            temp_i420_buffer_->GetStride(FrameBuffer::UPLANE),
            temp_i420_buffer_->GetData(FrameBuffer::VPLANE),
            temp_i420_buffer_->GetStride(FrameBuffer::VPLANE),
            temp_i420_buffer_->GetWidth(), temp_i420_buffer_->GetHeight());
        if (res != 0) {
          LOGF(ERROR) << "RGB24ToNV12() returns " << res;
          return -EINVAL;
        }
        res = libyuv::I420ToNV12(
            temp_i420_buffer_->GetData(FrameBuffer::YPLANE),
            temp_i420_buffer_->GetStride(FrameBuffer::YPLANE),
            temp_i420_buffer_->GetData(FrameBuffer::UPLANE),
            temp_i420_buffer_->GetStride(FrameBuffer::UPLANE),
            temp_i420_buffer_->GetData(FrameBuffer::VPLANE),
            temp_i420_buffer_->GetStride(FrameBuffer::VPLANE),
            out_frame.GetData(FrameBuffer::YPLANE),
            out_frame.GetStride(FrameBuffer::YPLANE),
            out_frame.GetData(FrameBuffer::UPLANE),
            out_frame.GetStride(FrameBuffer::UPLANE), out_frame.GetWidth(),
            out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "RGB24ToNV12() returns " << res;
        return res ? -EINVAL : 0;
      }
      default: {
        LOGF(ERROR) << "Not implemented: RGB24 -> " << out_frame.GetFourcc();
        return -EINVAL;
      }
    }
  } else if (in_frame.GetFourcc() == V4L2_PIX_FMT_INVZ ||
             in_frame.GetFourcc() == V4L2_PIX_FMT_Y16 ||
             in_frame.GetFourcc() == V4L2_PIX_FMT_Z16) {
    if (!temp_i420_buffer_gray_ ||
        temp_i420_buffer_gray_->GetWidth() != in_frame.GetWidth() ||
        temp_i420_buffer_gray_->GetHeight() != in_frame.GetHeight()) {
      if (!SharedFrameBuffer::Reallocate(
              in_frame.GetWidth(), in_frame.GetHeight(), V4L2_PIX_FMT_YUV420,
              &temp_i420_buffer_gray_)) {
        return -EINVAL;
      }

      // Fill UV plane with 0x80 to display in gray scale.
      memset(temp_i420_buffer_gray_->GetData(FrameBuffer::UPLANE), 0x80,
             temp_i420_buffer_gray_->GetStride(FrameBuffer::UPLANE) *
                 in_frame.GetHeight() / 2);
      memset(temp_i420_buffer_gray_->GetData(FrameBuffer::VPLANE), 0x80,
             temp_i420_buffer_gray_->GetStride(FrameBuffer::VPLANE) *
                 in_frame.GetHeight() / 2);
    }

    switch (out_frame.GetFourcc()) {
      case V4L2_PIX_FMT_YUV420:     // YU12
      case V4L2_PIX_FMT_YUV420M:    // YM12, multiple planes YU12
      case V4L2_PIX_FMT_YVU420:     // YV12
      case V4L2_PIX_FMT_YVU420M: {  // YM21, multiple planes YV12
        libyuv::Convert16To8Plane(
            reinterpret_cast<const uint16_t*>(in_frame.GetData()),
            in_frame.GetStride(), out_frame.GetData(FrameBuffer::YPLANE),
            out_frame.GetStride(FrameBuffer::YPLANE),
            256,  // scale
            in_frame.GetWidth(), in_frame.GetHeight());
        libyuv::CopyPlane(
            temp_i420_buffer_gray_->GetData(FrameBuffer::UPLANE),
            temp_i420_buffer_gray_->GetStride(FrameBuffer::UPLANE),
            out_frame.GetData(FrameBuffer::UPLANE),
            out_frame.GetStride(FrameBuffer::UPLANE),
            out_frame.GetStride(FrameBuffer::UPLANE),
            out_frame.GetHeight() / 2);
        libyuv::CopyPlane(
            temp_i420_buffer_gray_->GetData(FrameBuffer::VPLANE),
            temp_i420_buffer_gray_->GetStride(FrameBuffer::VPLANE),
            out_frame.GetData(FrameBuffer::VPLANE),
            out_frame.GetStride(FrameBuffer::VPLANE),
            out_frame.GetStride(FrameBuffer::VPLANE),
            out_frame.GetHeight() / 2);
        return 0;
      }
      case V4L2_PIX_FMT_NV12:     // NV12
      case V4L2_PIX_FMT_NV12M: {  // NM12
        libyuv::Convert16To8Plane(
            reinterpret_cast<const uint16_t*>(in_frame.GetData()),
            in_frame.GetStride(),
            temp_i420_buffer_gray_->GetData(FrameBuffer::YPLANE),
            temp_i420_buffer_gray_->GetStride(FrameBuffer::YPLANE),
            256,  // scale
            in_frame.GetWidth(), in_frame.GetHeight());

        int res = libyuv::I420ToNV12(
            temp_i420_buffer_gray_->GetData(FrameBuffer::YPLANE),
            temp_i420_buffer_gray_->GetStride(FrameBuffer::YPLANE),
            temp_i420_buffer_gray_->GetData(FrameBuffer::UPLANE),
            temp_i420_buffer_gray_->GetStride(FrameBuffer::UPLANE),
            temp_i420_buffer_gray_->GetData(FrameBuffer::VPLANE),
            temp_i420_buffer_gray_->GetStride(FrameBuffer::VPLANE),
            out_frame.GetData(FrameBuffer::YPLANE),
            out_frame.GetStride(FrameBuffer::YPLANE),
            out_frame.GetData(FrameBuffer::UPLANE),
            out_frame.GetStride(FrameBuffer::UPLANE), out_frame.GetWidth(),
            out_frame.GetHeight());
        LOGF_IF(ERROR, res) << "I420ToNV12() returns " << res;
        return res ? -EINVAL : 0;
      }
      default: {
        LOGF(ERROR) << "Not implemented: Y16/Z16 -> " << out_frame.GetFourcc();
        return -EINVAL;
      }
    }
  } else {
    LOGF(ERROR) << "Convert format doesn't support source format "
                << FormatToString(in_frame.GetFourcc());
    return -EINVAL;
  }
}

int ImageProcessor::Scale(FrameBuffer& in_frame, FrameBuffer& out_frame) {
  if (in_frame.Map() || out_frame.Map()) {
    LOGF(ERROR) << "Failed to map frame";
    return -EINVAL;
  }
  if (in_frame.GetFourcc() != V4L2_PIX_FMT_YUV420 &&
      in_frame.GetFourcc() != V4L2_PIX_FMT_YUV420M) {
    LOGF(ERROR) << "Pixel format " << FormatToString(in_frame.GetFourcc())
                << " is unsupported.";
    return -EINVAL;
  }

  VLOGF(1) << "Scale image from " << in_frame.GetWidth() << "x"
           << in_frame.GetHeight() << " to " << out_frame.GetWidth() << "x"
           << out_frame.GetHeight();

  int ret = libyuv::I420Scale(
      in_frame.GetData(FrameBuffer::YPLANE),
      in_frame.GetStride(FrameBuffer::YPLANE),
      in_frame.GetData(FrameBuffer::UPLANE),
      in_frame.GetStride(FrameBuffer::UPLANE),
      in_frame.GetData(FrameBuffer::VPLANE),
      in_frame.GetStride(FrameBuffer::VPLANE), in_frame.GetWidth(),
      in_frame.GetHeight(), out_frame.GetData(FrameBuffer::YPLANE),
      out_frame.GetStride(FrameBuffer::YPLANE),
      out_frame.GetData(FrameBuffer::UPLANE),
      out_frame.GetStride(FrameBuffer::UPLANE),
      out_frame.GetData(FrameBuffer::VPLANE),
      out_frame.GetStride(FrameBuffer::VPLANE), out_frame.GetWidth(),
      out_frame.GetHeight(), libyuv::FilterMode::kFilterNone);
  LOGF_IF(ERROR, ret) << "I420Scale failed: " << ret;
  return ret;
}

int ImageProcessor::ProcessForInsetPortraitMode(FrameBuffer& in_frame,
                                                FrameBuffer& out_frame,
                                                int rotate_degree) {
  if (in_frame.Map() || out_frame.Map()) {
    LOGF(ERROR) << "Failed to map frame";
    return -EINVAL;
  }

  libyuv::RotationMode rotation_mode = libyuv::RotationMode::kRotate90;
  switch (rotate_degree) {
    case 90:
      rotation_mode = libyuv::RotationMode::kRotate90;
      break;
    case 270:
      rotation_mode = libyuv::RotationMode::kRotate270;
      break;
    default:
      LOGF(ERROR) << "Invalid rotation degree: " << rotate_degree;
      return -EINVAL;
  }

  VLOGF(1) << "Crop and rotate image, rotate degree: " << rotate_degree;

  int margin = (in_frame.GetWidth() - out_frame.GetHeight()) / 2;
  // Crop from even pixels.
  margin &= ~1;

  if (in_frame.GetFourcc() == V4L2_PIX_FMT_YUV420 ||
      in_frame.GetFourcc() == V4L2_PIX_FMT_YUV420M) {
    int ret =
        I420Rotate(in_frame.GetData(FrameBuffer::YPLANE) + margin,
                   in_frame.GetStride(FrameBuffer::YPLANE),
                   in_frame.GetData(FrameBuffer::UPLANE) + margin / 2,
                   in_frame.GetStride(FrameBuffer::UPLANE),
                   in_frame.GetData(FrameBuffer::VPLANE) + margin / 2,
                   in_frame.GetStride(FrameBuffer::VPLANE),
                   out_frame.GetData(FrameBuffer::YPLANE),
                   out_frame.GetStride(FrameBuffer::YPLANE),
                   out_frame.GetData(FrameBuffer::UPLANE),
                   out_frame.GetStride(FrameBuffer::UPLANE),
                   out_frame.GetData(FrameBuffer::VPLANE),
                   out_frame.GetStride(FrameBuffer::VPLANE),
                   out_frame.GetHeight(), in_frame.GetHeight(), rotation_mode);
    if (ret) {
      LOGF(ERROR) << "I420Rotate failed: " << ret;
      return ret;
    }
  } else if (in_frame.GetFourcc() == V4L2_PIX_FMT_NV12 ||
             in_frame.GetFourcc() == V4L2_PIX_FMT_NV12M) {
    int ret = NV12ToI420Rotate(in_frame.GetData(FrameBuffer::YPLANE) + margin,
                               in_frame.GetStride(FrameBuffer::YPLANE),
                               in_frame.GetData(FrameBuffer::UPLANE) + margin,
                               in_frame.GetStride(FrameBuffer::UPLANE),
                               out_frame.GetData(FrameBuffer::YPLANE),
                               out_frame.GetStride(FrameBuffer::YPLANE),
                               out_frame.GetData(FrameBuffer::UPLANE),
                               out_frame.GetStride(FrameBuffer::UPLANE),
                               out_frame.GetData(FrameBuffer::VPLANE),
                               out_frame.GetStride(FrameBuffer::VPLANE),
                               out_frame.GetHeight(), in_frame.GetHeight(),
                               rotation_mode);
    if (ret) {
      LOGF(ERROR) << "NV12ToI420Rotate failed: " << ret;
      return ret;
    }
  } else {
    LOGF(ERROR) << "Pixel format " << FormatToString(in_frame.GetFourcc())
                << " is unsupported.";
    return -EINVAL;
  }
  return 0;
}

int ImageProcessor::Crop(FrameBuffer& in_frame, FrameBuffer& out_frame) {
  VLOGF(1) << "Crop from " << in_frame.GetWidth() << "x" << in_frame.GetHeight()
           << "," << FormatToString(in_frame.GetFourcc()) << " to "
           << out_frame.GetWidth() << "x" << out_frame.GetHeight() << ","
           << FormatToString(out_frame.GetFourcc());
  if (in_frame.Map() || out_frame.Map()) {
    LOGF(ERROR) << "Failed to map frame";
    return -EINVAL;
  }
  if (out_frame.GetWidth() > in_frame.GetWidth() ||
      out_frame.GetHeight() > in_frame.GetHeight()) {
    LOGF(ERROR) << "Crop to larger size";
    return -EINVAL;
  }

  int crop_x = (in_frame.GetWidth() - out_frame.GetWidth()) / 2;
  int crop_y = (in_frame.GetHeight() - out_frame.GetHeight()) / 2;
  // Crop from even pixels for correct YUV image.
  crop_x &= ~1;
  crop_y &= ~1;

  if (in_frame.GetFourcc() == V4L2_PIX_FMT_YUV420 ||
      in_frame.GetFourcc() == V4L2_PIX_FMT_YUV420M) {
    int ret = libyuv::I420Copy(
        in_frame.GetData(FrameBuffer::YPLANE) +
            in_frame.GetStride(FrameBuffer::YPLANE) * crop_y + crop_x,
        in_frame.GetStride(FrameBuffer::YPLANE),
        in_frame.GetData(FrameBuffer::UPLANE) +
            in_frame.GetStride(FrameBuffer::UPLANE) * crop_y / 2 + crop_x / 2,
        in_frame.GetStride(FrameBuffer::UPLANE),
        in_frame.GetData(FrameBuffer::VPLANE) +
            in_frame.GetStride(FrameBuffer::VPLANE) * crop_y / 2 + crop_x / 2,
        in_frame.GetStride(FrameBuffer::VPLANE),
        out_frame.GetData(FrameBuffer::YPLANE),
        out_frame.GetStride(FrameBuffer::YPLANE),
        out_frame.GetData(FrameBuffer::UPLANE),
        out_frame.GetStride(FrameBuffer::UPLANE),
        out_frame.GetData(FrameBuffer::VPLANE),
        out_frame.GetStride(FrameBuffer::VPLANE), out_frame.GetWidth(),
        out_frame.GetHeight());
    if (ret) {
      LOGF(ERROR) << "I420Copy failed: " << ret;
      return ret;
    }
  } else if (in_frame.GetFourcc() == V4L2_PIX_FMT_NV12 ||
             in_frame.GetFourcc() == V4L2_PIX_FMT_NV12M) {
    int ret = libyuv::NV12ToI420(
        in_frame.GetData(FrameBuffer::YPLANE) +
            in_frame.GetStride(FrameBuffer::YPLANE) * crop_y + crop_x,
        in_frame.GetStride(FrameBuffer::YPLANE),
        in_frame.GetData(FrameBuffer::UPLANE) +
            in_frame.GetStride(FrameBuffer::UPLANE) * crop_y / 2 + crop_x,
        in_frame.GetStride(FrameBuffer::UPLANE),
        out_frame.GetData(FrameBuffer::YPLANE),
        out_frame.GetStride(FrameBuffer::YPLANE),
        out_frame.GetData(FrameBuffer::UPLANE),
        out_frame.GetStride(FrameBuffer::UPLANE),
        out_frame.GetData(FrameBuffer::VPLANE),
        out_frame.GetStride(FrameBuffer::VPLANE), out_frame.GetWidth(),
        out_frame.GetHeight());
    if (ret) {
      LOGF(ERROR) << "NV12ToI420 failed: " << ret;
      return ret;
    }
  } else {
    LOGF(ERROR) << "Pixel format " << FormatToString(in_frame.GetFourcc())
                << " is unsupported.";
    return -EINVAL;
  }
  return 0;
}

}  // namespace cros
