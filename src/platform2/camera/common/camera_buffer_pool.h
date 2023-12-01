/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_BUFFER_POOL_H_
#define CAMERA_COMMON_CAMERA_BUFFER_POOL_H_

#include <stddef.h>
#include <stdint.h>

#include <list>
#include <optional>
#include <utility>

#include "cros-camera/camera_buffer_manager.h"

namespace cros {

// CameraBufferPool owns a number of lazily allocated buffers, and provides
// unique access to the buffer handles.  This class and its returned objects are
// not thread-safe and the caller needs to ensure access to the buffers is
// synchronized.
class CameraBufferPool {
 private:
  class BufferSlot;

 public:
  // Buffer holds the requested buffer handle and automatically releases it back
  // to the pool when destructed.
  class Buffer {
   public:
    explicit Buffer(BufferSlot* slot);
    ~Buffer();

    Buffer(const Buffer&) = delete;
    Buffer& operator=(const Buffer&) = delete;

    Buffer(Buffer&&);
    Buffer& operator=(Buffer&&);

    // Map/Unmap the buffer.  The mapped state is kept after releasing the
    // buffer, and is re-used when the same buffer is acquired next time.
    const ScopedMapping& Map() { return slot_->Map(); }
    void Unmap() { slot_->Unmap(); }

    buffer_handle_t* handle() const { return slot_->handle(); }

   private:
    BufferSlot* slot_ = nullptr;
  };

  struct Options {
    // Buffer parameters that will be used to allocate buffers with
    // CameraBufferManager.
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t format = 0;
    uint32_t usage = 0;

    // The maximum number of buffers that can be allocated in the pool.
    size_t max_num_buffers = 0;
  };

  explicit CameraBufferPool(const Options& options) : options_(options) {}

  ~CameraBufferPool();

  CameraBufferPool(const CameraBufferPool&) = delete;
  CameraBufferPool(CameraBufferPool&&) = delete;
  CameraBufferPool& operator=(const CameraBufferPool&) = delete;
  CameraBufferPool& operator=(CameraBufferPool&&) = delete;

  // Returns a Buffer, or nullopt if the number of buffers in use reaches
  // maximum.  The returned Buffer cannot out-live this class.
  std::optional<Buffer> RequestBuffer();

 private:
  class BufferSlot {
   public:
    explicit BufferSlot(ScopedBufferHandle handle);

    Buffer Acquire();
    void Release();

    const ScopedMapping& Map();
    void Unmap();

    buffer_handle_t* handle() const { return handle_.get(); }
    bool is_acquired() const { return is_acquired_; }

   private:
    ScopedBufferHandle handle_;
    std::optional<ScopedMapping> mapping_;
    bool is_acquired_ = false;
  };

  Options options_;

  // Use std::list for pointer stability.
  std::list<BufferSlot> buffer_slots_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_CAMERA_BUFFER_POOL_H_
