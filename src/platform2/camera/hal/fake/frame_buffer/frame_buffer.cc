/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/fake/frame_buffer/frame_buffer.h"

#include <utility>
#include <vector>

#include <base/bits.h>
#include <libyuv.h>

#include "cros-camera/jpeg_compressor.h"
#include "hal/fake/camera_hal.h"

namespace cros {

namespace {

bool ConvertNv12ToJpeg(FrameBuffer& buffer, FrameBuffer& output_buffer) {
  auto jpeg_compressor = JpegCompressor::GetInstance(
      CameraHal::GetInstance().GetMojoManagerToken());
  uint32_t out_data_size;

  std::vector<uint8_t> app1;

  // TODO(pihsun): Fill thumbnail in app1.
  // TODO(pihsun): Should use android.jpeg.quality in request metadata for
  // JPEG quality.
  auto gralloc_buffer = dynamic_cast<GrallocFrameBuffer*>(&buffer);
  auto gralloc_output_buffer =
      dynamic_cast<GrallocFrameBuffer*>(&output_buffer);
  if (gralloc_buffer != nullptr && gralloc_output_buffer != nullptr) {
    bool success = jpeg_compressor->CompressImageFromHandle(
        gralloc_buffer->GetBufferHandle(),
        gralloc_output_buffer->GetBufferHandle(),
        gralloc_buffer->GetSize().width, gralloc_buffer->GetSize().height,
        /*quality=*/90, app1.data(), app1.size(), &out_data_size);
    if (!success) {
      LOGF(WARNING) << "failed to encode JPEG";
      return false;
    }
  } else {
    // TODO(pihsun): Use jpeg_compressor->CompressImageFromMemory in this
    // case.
    LOGF(WARNING)
        << "Non GrallocFrameBuffer for JPEG encoding is not supported (yet)";
    return false;
  }

  // Fill camera3_jpeg_blob_t trailer
  auto mapped_output_buffer = output_buffer.Map();
  if (mapped_output_buffer == nullptr) {
    LOGF(WARNING) << "failed to map the output buffer";
    return false;
  }

  auto data = mapped_output_buffer->plane(0).addr;
  auto output_buffer_size = mapped_output_buffer->plane(0).size;

  camera3_jpeg_blob_t blob = {
      .jpeg_blob_id = CAMERA3_JPEG_BLOB_ID,
      .jpeg_size = out_data_size,
  };

  if (base::ClampAdd(out_data_size, sizeof(blob)) > output_buffer_size) {
    LOGF(WARNING) << "Encoded jpeg size " << out_data_size
                  << " can't fit into output buffer of size "
                  << output_buffer_size;
    return false;
  }
  memcpy(data + output_buffer_size - sizeof(blob), &blob, sizeof(blob));

  return true;
}

}  // namespace

FrameBuffer::ScopedMapping::ScopedMapping() = default;
FrameBuffer::ScopedMapping::~ScopedMapping() = default;

FrameBuffer::FrameBuffer() = default;
FrameBuffer::~FrameBuffer() = default;

// static
bool FrameBuffer::ScaleInto(FrameBuffer& buffer,
                            FrameBuffer& output_buffer,
                            ScaleMode scale_mode) {
  if (buffer.GetFourcc() != V4L2_PIX_FMT_NV12 ||
      output_buffer.GetFourcc() != V4L2_PIX_FMT_NV12) {
    LOGF(WARNING) << "Only V4L2_PIX_FMT_NV12 is supported for resize";
    return false;
  }

  Size size = buffer.GetSize();
  Size output_size = output_buffer.GetSize();

  if (output_size.width % 2 != 0 || output_size.height % 2 != 0) {
    LOGF(WARNING) << "Output width and height should both be even";
    return false;
  }

  auto mapped_buffer = buffer.Map();
  if (mapped_buffer == nullptr) {
    LOGF(WARNING) << "Failed to map temporary buffer";
    return false;
  }

  auto y_plane = mapped_buffer->plane(0);
  auto uv_plane = mapped_buffer->plane(1);

  auto mapped_output_buffer = output_buffer.Map();
  if (mapped_output_buffer == nullptr) {
    LOGF(WARNING) << "Failed to map buffer";
    return false;
  }

  auto output_y_plane = mapped_output_buffer->plane(0);
  auto output_uv_plane = mapped_output_buffer->plane(1);

  switch (scale_mode) {
    case ScaleMode::kStretch: {
      int ret = libyuv::NV12Scale(
          y_plane.addr, y_plane.stride, uv_plane.addr, uv_plane.stride,
          size.width, size.height, output_y_plane.addr, output_y_plane.stride,
          output_uv_plane.addr, output_uv_plane.stride, output_size.width,
          output_size.height, libyuv::kFilterBilinear);
      if (ret != 0) {
        LOGF(WARNING) << "NV12Scale() failed with " << ret;
        return false;
      }
      return true;
    }
    case ScaleMode::kContain: {
      double aspect_ratio = size.aspect_ratio();
      uint32_t target_width = std::min(
          output_size.width,
          base::bits::AlignUp(static_cast<uint32_t>(
                                  std::ceil(output_size.height * aspect_ratio)),
                              2u));
      uint32_t target_height = std::min(
          output_size.height,
          base::bits::AlignUp(static_cast<uint32_t>(
                                  std::ceil(output_size.width / aspect_ratio)),
                              2u));
      uint32_t target_x =
          base::bits::AlignDown((output_size.width - target_width) / 2, 2u);
      uint32_t target_y =
          base::bits::AlignDown((output_size.height - target_height) / 2, 2u);

      // Sets the output buffer to black (y = 0, u = v = 128).
      // TODO(pihsun): Support setting other colors.
      libyuv::SetPlane(output_y_plane.addr, output_y_plane.stride,
                       output_size.width, output_size.height, 0);
      libyuv::SetPlane(output_uv_plane.addr, output_uv_plane.stride,
                       output_size.width, output_size.height / 2, 128);

      int ret = libyuv::NV12Scale(
          y_plane.addr, y_plane.stride, uv_plane.addr, uv_plane.stride,
          size.width, size.height,
          output_y_plane.addr + target_x + target_y * output_y_plane.stride,
          output_y_plane.stride,
          output_uv_plane.addr + target_x +
              target_y / 2 * output_uv_plane.stride,
          output_uv_plane.stride, target_width, target_height,
          libyuv::kFilterBilinear);
      if (ret != 0) {
        LOGF(WARNING) << "NV12Scale() failed with " << ret;
        return false;
      }
      return true;
    }
    case ScaleMode::kCover: {
      double aspect_ratio = output_size.aspect_ratio();
      uint32_t src_width = std::min(
          size.width,
          base::bits::AlignUp(
              static_cast<uint32_t>(std::ceil(size.height * aspect_ratio)),
              2u));
      uint32_t src_height = std::min(
          size.height,
          base::bits::AlignUp(
              static_cast<uint32_t>(std::ceil(size.width / aspect_ratio)), 2u));
      uint32_t src_x = base::bits::AlignDown((size.width - src_width) / 2, 2u);
      uint32_t src_y =
          base::bits::AlignDown((size.height - src_height) / 2, 2u);

      int ret = libyuv::NV12Scale(
          y_plane.addr + src_x + src_y * y_plane.stride, y_plane.stride,
          uv_plane.addr + src_x + src_y / 2 * uv_plane.stride, uv_plane.stride,
          src_width, src_height, output_y_plane.addr, output_y_plane.stride,
          output_uv_plane.addr, output_uv_plane.stride, output_size.width,
          output_size.height, libyuv::kFilterBilinear);
      if (ret != 0) {
        LOGF(WARNING) << "NV12Scale() failed with " << ret;
        return false;
      }
      return true;
    }
    default:
      NOTREACHED() << "Unknown scale mode " << static_cast<int>(scale_mode);
      return false;
  }
}

// static
bool FrameBuffer::ConvertFromNv12(FrameBuffer& buffer,
                                  FrameBuffer& output_buffer) {
  CHECK_EQ(buffer.GetFourcc(), V4L2_PIX_FMT_NV12);

  auto output_buffer_fourcc = output_buffer.GetFourcc();

  if (output_buffer_fourcc == V4L2_PIX_FMT_JPEG) {
    return ConvertNv12ToJpeg(buffer, output_buffer);
  }

  auto size = buffer.GetSize();
  if (size != output_buffer.GetSize()) {
    LOGF(WARNING) << "Can't copy buffer of size " << size.ToString() << " to "
                  << output_buffer.GetSize().ToString();
    return false;
  }

  auto mapped_buffer = buffer.Map();
  if (mapped_buffer == nullptr) {
    LOGF(WARNING) << "Failed to map the buffer";
    return false;
  }
  auto y_plane = mapped_buffer->plane(0);
  auto uv_plane = mapped_buffer->plane(1);

  auto mapped_output_buffer = output_buffer.Map();
  if (mapped_output_buffer == nullptr) {
    LOGF(WARNING) << "Failed to map the output buffer";
    return false;
  }

  switch (output_buffer_fourcc) {
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M: {
      // NV12 -> NV12
      auto output_y_plane = mapped_output_buffer->plane(0);
      auto output_uv_plane = mapped_output_buffer->plane(1);
      int ret = libyuv::NV12Copy(
          y_plane.addr, y_plane.stride, uv_plane.addr, uv_plane.stride,
          output_y_plane.addr, output_y_plane.stride, output_uv_plane.addr,
          output_uv_plane.stride, size.width, size.height);
      if (ret != 0) {
        LOGF(WARNING) << "NV12Copy() failed with " << ret;
        return false;
      }
      return true;
    }
    case V4L2_PIX_FMT_YUV420:
    case V4L2_PIX_FMT_YUV420M: {
      // NV12 -> YUV420
      auto output_y_plane = mapped_output_buffer->plane(0);
      auto output_u_plane = mapped_output_buffer->plane(1);
      auto output_v_plane = mapped_output_buffer->plane(2);
      int ret = libyuv::NV12ToI420(
          y_plane.addr, y_plane.stride, uv_plane.addr, uv_plane.stride,
          output_y_plane.addr, output_y_plane.stride, output_u_plane.addr,
          output_u_plane.stride, output_v_plane.addr, output_v_plane.stride,
          size.width, size.height);
      if (ret != 0) {
        LOGF(WARNING) << "NV12ToI420() failed with " << ret;
        return false;
      }
      return true;
    }
    case V4L2_PIX_FMT_YVU420:
    case V4L2_PIX_FMT_YVU420M: {
      // NV12 -> YVU420
      auto output_y_plane = mapped_output_buffer->plane(0);
      auto output_u_plane = mapped_output_buffer->plane(2);
      auto output_v_plane = mapped_output_buffer->plane(1);
      int ret = libyuv::NV12ToI420(
          y_plane.addr, y_plane.stride, uv_plane.addr, uv_plane.stride,
          output_y_plane.addr, output_y_plane.stride, output_u_plane.addr,
          output_u_plane.stride, output_v_plane.addr, output_v_plane.stride,
          size.width, size.height);
      if (ret != 0) {
        LOGF(WARNING) << "NV12ToI420() failed with " << ret;
        return false;
      }
      return true;
    }
    case V4L2_PIX_FMT_RGBX32: {
      // NV12 -> RGBX32
      auto rgbx = mapped_output_buffer->plane(0);

      int ret = libyuv::NV12ToABGR(y_plane.addr, y_plane.stride, uv_plane.addr,
                                   uv_plane.stride, rgbx.addr, rgbx.stride,
                                   size.width, size.height);
      if (ret != 0) {
        LOGF(WARNING) << "NV12ToABGR() failed with " << ret;
        return false;
      }
      return true;
    }
  }

  LOGF(WARNING) << "Unsupported conversion from NV12 to "
                << FormatToString(output_buffer_fourcc);
  return false;
}

bool FrameBuffer::ConvertToNv12(FrameBuffer& buffer,
                                FrameBuffer& output_buffer) {
  CHECK_EQ(output_buffer.GetFourcc(), V4L2_PIX_FMT_NV12);

  auto buffer_fourcc = buffer.GetFourcc();

  if (buffer_fourcc == V4L2_PIX_FMT_JPEG) {
    // TODO(pihsun): Implement this if there's any user that use this.
    LOGF(WARNING) << "Converting from JPEG isn't implemented.";
    return false;
  }

  auto size = buffer.GetSize();
  if (size != output_buffer.GetSize()) {
    LOGF(WARNING) << "Can't copy buffer of size " << size.ToString() << " to "
                  << output_buffer.GetSize().ToString();
    return false;
  }

  auto mapped_buffer = buffer.Map();
  if (mapped_buffer == nullptr) {
    LOGF(WARNING) << "Failed to map the buffer";
    return false;
  }

  auto mapped_output_buffer = output_buffer.Map();
  if (mapped_output_buffer == nullptr) {
    LOGF(WARNING) << "Failed to map the output buffer";
    return false;
  }

  auto output_y_plane = mapped_output_buffer->plane(0);
  auto output_uv_plane = mapped_output_buffer->plane(1);

  switch (buffer_fourcc) {
    case V4L2_PIX_FMT_NV12:
    case V4L2_PIX_FMT_NV12M: {
      // NV12 -> NV12
      auto y_plane = mapped_buffer->plane(0);
      auto uv_plane = mapped_buffer->plane(1);
      int ret = libyuv::NV12Copy(
          y_plane.addr, y_plane.stride, uv_plane.addr, uv_plane.stride,
          output_y_plane.addr, output_y_plane.stride, output_uv_plane.addr,
          output_uv_plane.stride, size.width, size.height);
      if (ret != 0) {
        LOGF(WARNING) << "NV12Copy() failed with " << ret;
        return false;
      }
      return true;
    }
    case V4L2_PIX_FMT_YUV420:
    case V4L2_PIX_FMT_YUV420M: {
      // YUV420 -> NV12
      auto y_plane = mapped_buffer->plane(0);
      auto u_plane = mapped_buffer->plane(1);
      auto v_plane = mapped_buffer->plane(2);
      int ret = libyuv::I420ToNV12(y_plane.addr, y_plane.stride, u_plane.addr,
                                   u_plane.stride, v_plane.addr, v_plane.stride,
                                   output_y_plane.addr, output_y_plane.stride,
                                   output_uv_plane.addr, output_uv_plane.stride,
                                   size.width, size.height);
      if (ret != 0) {
        LOGF(WARNING) << "I420ToNV12() failed with " << ret;
        return false;
      }
      return true;
    }
    case V4L2_PIX_FMT_YVU420:
    case V4L2_PIX_FMT_YVU420M: {
      // YVU420 -> NV12
      auto y_plane = mapped_buffer->plane(0);
      auto u_plane = mapped_buffer->plane(2);
      auto v_plane = mapped_buffer->plane(1);
      int ret = libyuv::I420ToNV12(y_plane.addr, y_plane.stride, u_plane.addr,
                                   u_plane.stride, v_plane.addr, v_plane.stride,
                                   output_y_plane.addr, output_y_plane.stride,
                                   output_uv_plane.addr, output_uv_plane.stride,
                                   size.width, size.height);
      if (ret != 0) {
        LOGF(WARNING) << "I420ToNV12() failed with " << ret;
        return false;
      }
      return true;
    }
  }

  LOGF(WARNING) << "Unsupported conversion from "
                << FormatToString(buffer_fourcc) << " to NV12";
  return false;
}

}  // namespace cros
