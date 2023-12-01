/* Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_FAKE_FRAME_BUFFER_CPU_MEMORY_FRAME_BUFFER_H_
#define CAMERA_HAL_FAKE_FRAME_BUFFER_CPU_MEMORY_FRAME_BUFFER_H_

#include <memory>
#include <utility>
#include <vector>

#include <base/memory/safe_ref.h>
#include <base/memory/weak_ptr.h>
#include <base/sequence_checker.h>

#include "cros-camera/common_types.h"

#include "hal/fake/frame_buffer/frame_buffer.h"

namespace cros {

// InMemoryFrameBuffer allocates memory on heap.
// The class is not thread safe and all methods should be run on the same
// sequence.
class CpuMemoryFrameBuffer : public FrameBuffer {
 public:
  class ScopedMapping : public FrameBuffer::ScopedMapping {
   public:
    ~ScopedMapping() override;

    uint32_t num_planes() const override;

    Plane plane(int plane) const override;

   private:
    friend class CpuMemoryFrameBuffer;

    explicit ScopedMapping(base::SafeRef<CpuMemoryFrameBuffer> buffer);

    base::SafeRef<CpuMemoryFrameBuffer> buffer_;
  };

  ~CpuMemoryFrameBuffer() override;

  // Returns the mapped buffer, or nullptr if map failed. The return value
  // should not outlive |this|.
  std::unique_ptr<FrameBuffer::ScopedMapping> Map() override;

 private:
  friend class FrameBuffer;

  CpuMemoryFrameBuffer();

  // Allocate the buffer.
  [[nodiscard]] bool Initialize(Size size, uint32_t fourcc) override;

  friend class ScopedMapping;

  // Data of the buffer that all planes points to.
  // unique_ptr<uint8_t[]> instead of vector<uint8_t> is used here to avoid
  // accidentally copying the data, invalidating the address in plane.
  std::unique_ptr<uint8_t[]> data_;

  // Planes of the buffer.
  std::vector<ScopedMapping::Plane> planes_;

  // Allocates memory that can fit all the planes with given sizes, and set
  // each plane address accordingly. This sets |data_| and |planes_|.
  void AllocatePlanes(base::span<const Size> sizes);

  // Use to check all methods are called on the same thread.
  SEQUENCE_CHECKER(sequence_checker_);

  base::WeakPtrFactory<CpuMemoryFrameBuffer> weak_ptr_factory_{this};
};

}  // namespace cros

#endif  // CAMERA_HAL_FAKE_FRAME_BUFFER_CPU_MEMORY_FRAME_BUFFER_H_
