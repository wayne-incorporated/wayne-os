/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_FRAME_BUFFER_GRALLOC_FRAME_BUFFER_H_
#define CAMERA_HAL_FAKE_FRAME_BUFFER_GRALLOC_FRAME_BUFFER_H_

#include <memory>

#include <absl/status/statusor.h>
#include <base/sequence_checker.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/common_types.h"

#include "hal/fake/frame_buffer/frame_buffer.h"

namespace cros {

// GrallocFrameBuffer uses CameraBufferManager to manage the buffer.
// The class is not thread safe and all methods should be run on the same
// sequence.
class GrallocFrameBuffer : public FrameBuffer {
 public:
  class ScopedMapping : public FrameBuffer::ScopedMapping {
   public:
    ~ScopedMapping() override;

    uint32_t num_planes() const override;

    Plane plane(int plane) const override;

    static std::unique_ptr<ScopedMapping> Create(buffer_handle_t);

   private:
    explicit ScopedMapping(buffer_handle_t buffer);

    bool is_valid() const;

    cros::ScopedMapping scoped_mapping_;
  };

  ~GrallocFrameBuffer() override;

  // Returns the mapped buffer, or nullptr if map failed. The return value
  // should not outlive |this|.
  std::unique_ptr<FrameBuffer::ScopedMapping> Map() override;

  // Gets the underlying buffer handle.
  buffer_handle_t GetBufferHandle() const { return buffer_; }

  // Wraps external buffer from upper framework. Fill |size_| according to the
  // buffer size. Returns nullptr when there's error.
  static std::unique_ptr<GrallocFrameBuffer> Wrap(buffer_handle_t buffer);

 private:
  friend class FrameBuffer;

  GrallocFrameBuffer();

  // Wraps external buffer from upper framework. Fill |size_| according to the
  // buffer size.
  [[nodiscard]] bool Initialize(buffer_handle_t buffer);

  // Allocate the buffer internally.
  [[nodiscard]] bool Initialize(Size size, uint32_t fourcc) override;

  // The currently used buffer.
  buffer_handle_t buffer_ = nullptr;

  // Used to import gralloc buffer.
  CameraBufferManager* buffer_manager_;

  // Whether the |buffer_| is allocated by this class.
  bool is_buffer_owned_ = false;

  // Use to check all methods are called on the same thread.
  SEQUENCE_CHECKER(sequence_checker_);
};

}  // namespace cros

#endif  // CAMERA_HAL_FAKE_FRAME_BUFFER_GRALLOC_FRAME_BUFFER_H_
