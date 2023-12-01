/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_FAKE_STREAM_H_
#define CAMERA_HAL_FAKE_FAKE_STREAM_H_

#include <memory>

#include <camera/camera_metadata.h>
#include <hardware/camera3.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/common_types.h"
#include "hal/fake/frame_buffer/gralloc_frame_buffer.h"
#include "hal/fake/hal_spec.h"

namespace cros {

// Maximum allowed frame size for the stream for safety purpose, to avoid
// accidentally passed in wrong frame file and allocate a large amount of
// memory.
constexpr size_t kFrameMaxDimension = 8192;

class FakeStream {
 public:
  FakeStream(FakeStream&&) = delete;
  FakeStream& operator=(FakeStream&&) = delete;

  FakeStream(const FakeStream&) = delete;
  FakeStream& operator=(const FakeStream&) = delete;

  virtual ~FakeStream();

  // Factory method to create a FakeStream, might return null on error.
  static std::unique_ptr<FakeStream> Create(Size size, const FramesSpec& spec);

  // Fills the buffer with the next frame from the fake stream. The buffer
  // format should match the format specified in the constructor.
  [[nodiscard]] virtual bool FillBuffer(buffer_handle_t buffer) = 0;

 protected:
  FakeStream();

  CameraBufferManager* buffer_manager_;

  Size size_;

  [[nodiscard]] virtual bool Initialize(Size size, const FramesSpec& spec);
};

class StaticFakeStream : public FakeStream {
 protected:
  friend class FakeStream;
  // |buffer| should be in V4L2_PIX_FMT_NV12 format.
  explicit StaticFakeStream(std::unique_ptr<GrallocFrameBuffer> buffer);

  [[nodiscard]] bool FillBuffer(buffer_handle_t buffer) override;

 private:
  std::unique_ptr<GrallocFrameBuffer> buffer_;
};
}  // namespace cros

#endif  // CAMERA_HAL_FAKE_FAKE_STREAM_H_
