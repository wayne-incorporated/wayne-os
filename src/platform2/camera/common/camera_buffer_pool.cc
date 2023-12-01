/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "camera/common/camera_buffer_pool.h"

#include <optional>

#include "cros-camera/common.h"

namespace cros {

CameraBufferPool::Buffer::Buffer(BufferSlot* slot) : slot_(slot) {
  DCHECK_NE(slot_, nullptr);
}

CameraBufferPool::Buffer::~Buffer() {
  if (slot_) {
    slot_->Release();
  }
}

CameraBufferPool::Buffer::Buffer(Buffer&& other) {
  *this = std::move(other);
}

CameraBufferPool::Buffer& CameraBufferPool::Buffer::operator=(Buffer&& other) {
  if (this != &other) {
    DCHECK_NE(slot_, other.slot_);
    if (slot_) {
      slot_->Release();
    }
    slot_ = other.slot_;
    other.slot_ = nullptr;
  }
  return *this;
}

CameraBufferPool::BufferSlot::BufferSlot(ScopedBufferHandle handle)
    : handle_(std::move(handle)) {}

CameraBufferPool::Buffer CameraBufferPool::BufferSlot::Acquire() {
  DCHECK(!is_acquired_);
  is_acquired_ = true;
  return Buffer(this);
}

void CameraBufferPool::BufferSlot::Release() {
  DCHECK(is_acquired_);
  is_acquired_ = false;
}

const ScopedMapping& CameraBufferPool::BufferSlot::Map() {
  if (!mapping_) {
    mapping_ = std::make_optional<ScopedMapping>(*handle_);
  }
  return *mapping_;
}

void CameraBufferPool::BufferSlot::Unmap() {
  mapping_.reset();
}

CameraBufferPool::~CameraBufferPool() {
  auto it =
      std::find_if(buffer_slots_.begin(), buffer_slots_.end(),
                   [](const BufferSlot& slot) { return slot.is_acquired(); });
  if (it != buffer_slots_.end()) {
    LOGF(FATAL) << "CameraBufferPool destructed when there's buffer in use";
  }
}

std::optional<CameraBufferPool::Buffer> CameraBufferPool::RequestBuffer() {
  auto it =
      std::find_if(buffer_slots_.begin(), buffer_slots_.end(),
                   [](const BufferSlot& slot) { return !slot.is_acquired(); });
  if (it != buffer_slots_.end()) {
    return it->Acquire();
  }
  if (buffer_slots_.size() < options_.max_num_buffers) {
    ScopedBufferHandle handle = CameraBufferManager::AllocateScopedBuffer(
        options_.width, options_.height, options_.format, options_.usage);
    if (!handle) {
      return std::nullopt;
    }
    buffer_slots_.emplace_back(std::move(handle));
    VLOGF(1) << "Increased pool buffer count to " << buffer_slots_.size();
    return buffer_slots_.back().Acquire();
  }
  VLOGF(1) << "Buffer pool ran out of free buffers";
  return std::nullopt;
}

}  // namespace cros
