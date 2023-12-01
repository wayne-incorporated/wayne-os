/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/fake/fake_stream.h"

#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/memory/ptr_util.h>
#include <base/notreached.h>
#include <base/numerics/clamped_math.h>
#include <base/timer/elapsed_timer.h>
#include <libyuv.h>
#include <linux/videodev2.h>

#include "hal/fake/camera_hal.h"
#include "hal/fake/frame_buffer/gralloc_frame_buffer.h"
#include "hal/fake/test_pattern.h"
#include "hal/fake/y4m_fake_stream.h"

namespace cros {

namespace {
std::unique_ptr<GrallocFrameBuffer> ReadAndScaleMJPGFromFile(
    const base::FilePath& path, Size size, ScaleMode scale_mode) {
  auto bytes = base::ReadFileToBytes(path);
  if (!bytes.has_value()) {
    LOGF(WARNING) << "Failed to read file: " << path;
    return nullptr;
  }
  int width, height;
  if (libyuv::MJPGSize(bytes->data(), bytes->size(), &width, &height) != 0) {
    LOGF(WARNING) << "Failed to get MJPG size: " << path;
    return nullptr;
  }
  CHECK(width > 0 && height > 0);
  if (width > kFrameMaxDimension || height > kFrameMaxDimension) {
    LOGF(WARNING) << "Image size too large: " << path;
    return nullptr;
  }

  auto temp_buffer = FrameBuffer::Create<GrallocFrameBuffer>(
      Size(width, height), V4L2_PIX_FMT_NV12);
  if (temp_buffer == nullptr) {
    LOGF(WARNING) << "Failed to create temporary buffer";
    return nullptr;
  }

  auto mapped_temp_buffer = temp_buffer->Map();
  if (mapped_temp_buffer == nullptr) {
    LOGF(WARNING) << "Failed to map temporary buffer";
    return nullptr;
  }

  auto temp_y_plane = mapped_temp_buffer->plane(0);
  auto temp_uv_plane = mapped_temp_buffer->plane(1);

  int ret = libyuv::MJPGToNV12(
      bytes->data(), bytes->size(), temp_y_plane.addr, temp_y_plane.stride,
      temp_uv_plane.addr, temp_uv_plane.stride, width, height, width, height);
  if (ret != 0) {
    LOGF(WARNING) << "MJPGToNV12() failed with " << ret;
    return nullptr;
  }

  return FrameBuffer::Scale<GrallocFrameBuffer>(*temp_buffer, size, scale_mode);
}
}  // namespace

FakeStream::FakeStream()
    : buffer_manager_(CameraBufferManager::GetInstance()) {}

FakeStream::~FakeStream() = default;

template <class... Ts>
struct Overloaded : Ts... {
  using Ts::operator()...;
};
template <class... Ts>
Overloaded(Ts...) -> Overloaded<Ts...>;

// static
std::unique_ptr<FakeStream> FakeStream::Create(Size size,
                                               const FramesSpec& spec) {
  std::unique_ptr<FakeStream> fake_stream = std::visit(
      Overloaded{
          [&size](const FramesTestPatternSpec& spec)
              -> std::unique_ptr<FakeStream> {
            auto input_buffer = GenerateTestPattern(
                size, ANDROID_SENSOR_TEST_PATTERN_MODE_COLOR_BARS_FADE_TO_GRAY);
            return base::WrapUnique(
                new StaticFakeStream(std::move(input_buffer)));
          },
          [&size](const FramesFileSpec& spec) -> std::unique_ptr<FakeStream> {
            auto extension = spec.path.Extension();
            if (extension == ".jpg" || extension == ".jpeg" ||
                extension == ".mjpg" || extension == ".mjpeg") {
              // TODO(pihsun): This only reads a single frame now, read and
              // convert the whole stream on fly.
              auto input_buffer =
                  ReadAndScaleMJPGFromFile(spec.path, size, spec.scale_mode);
              return base::WrapUnique(
                  new StaticFakeStream(std::move(input_buffer)));
            } else if (extension == ".y4m") {
              return base::WrapUnique(
                  new Y4mFakeStream(spec.path, spec.scale_mode));
            } else {
              LOGF(WARNING) << "Unknown file extension: " << extension;
              return nullptr;
            }
          },
      },
      spec);
  if (fake_stream == nullptr || !fake_stream->Initialize(size, spec)) {
    return nullptr;
  }
  return fake_stream;
}

bool FakeStream::Initialize(Size size, const FramesSpec& spec) {
  size_ = size;
  return true;
}

StaticFakeStream::StaticFakeStream(std::unique_ptr<GrallocFrameBuffer> buffer)
    : buffer_(std::move(buffer)) {}

bool StaticFakeStream::FillBuffer(buffer_handle_t output_buffer_handle) {
  auto output_buffer = GrallocFrameBuffer::Wrap(output_buffer_handle);
  if (output_buffer == nullptr) {
    LOGF(WARNING) << "Failed to wrap output buffer";
    return false;
  }
  return FrameBuffer::ConvertFromNv12(*buffer_, *output_buffer);
}

}  // namespace cros
