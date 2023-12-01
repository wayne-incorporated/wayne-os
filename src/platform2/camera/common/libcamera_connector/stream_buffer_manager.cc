/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <utility>

#include <base/files/file_util.h>
#include <mojo/public/cpp/system/platform_handle.h>

#include "common/libcamera_connector/stream_buffer_manager.h"
#include "cros-camera/common.h"

namespace cros {

StreamBufferManager::StreamBufferManager() : callback_thread_("StreamBufMgr") {
  callback_thread_.Start();
}

StreamBufferManager::~StreamBufferManager() {
  callback_thread_.Stop();
}

void StreamBufferManager::Init(
    std::vector<mojom::Camera3StreamBufferPtr> allocated_buffers) {
  base::AutoLock l(buffer_manager_lock_);

  std::queue<mojom::Camera3StreamBufferPtr*>().swap(buffer_queue_);
  buffer_pointer_map_.clear();
  fd_map_.clear();
  notify_callback_.Reset();

  buffers_ = std::move(allocated_buffers);
  for (auto& stream_buffer : buffers_) {
    buffer_queue_.push(&stream_buffer);
    buffer_pointer_map_[stream_buffer->buffer_id] = &stream_buffer;
    for (auto& fd : stream_buffer->buffer_handle->fds) {
      fd_map_[stream_buffer->buffer_id].emplace_back(
          mojo::UnwrapPlatformHandle(std::move(fd)).TakeFD());
    }
  }
}

mojom::Camera3StreamBufferPtr StreamBufferManager::AllocateBuffer() {
  base::AutoLock l(buffer_manager_lock_);

  if (buffer_queue_.empty()) {
    return nullptr;
  }

  const auto& pool_stream_buffer = *buffer_queue_.front();
  auto& pool_buffer_handle = pool_stream_buffer->buffer_handle;
  auto buffer_handle = mojom::CameraBufferHandle::New();
  buffer_handle->buffer_id = pool_buffer_handle->buffer_id;
  buffer_handle->drm_format = pool_buffer_handle->drm_format;
  buffer_handle->hal_pixel_format = pool_buffer_handle->hal_pixel_format;
  buffer_handle->width = pool_buffer_handle->width;
  buffer_handle->height = pool_buffer_handle->height;
  buffer_handle->sizes = std::vector<uint32_t>();
  for (size_t i = 0; i < pool_buffer_handle->fds.size(); ++i) {
    buffer_handle->fds.push_back(
        mojo::WrapPlatformFile(base::ScopedPlatformFile(HANDLE_EINTR(
            dup(fd_map_[pool_buffer_handle->buffer_id][i].get())))));
    buffer_handle->strides.push_back(pool_buffer_handle->strides[i]);
    buffer_handle->offsets.push_back(pool_buffer_handle->offsets[i]);
    buffer_handle->sizes->push_back(pool_buffer_handle->sizes->at(i));
  }

  mojom::Camera3StreamBufferPtr stream_buffer =
      mojom::Camera3StreamBuffer::New();
  stream_buffer->stream_id = pool_stream_buffer->stream_id;
  stream_buffer->buffer_id = pool_stream_buffer->buffer_id;
  stream_buffer->status = mojom::Camera3BufferStatus::CAMERA3_BUFFER_STATUS_OK;
  stream_buffer->buffer_handle = std::move(buffer_handle);

  buffer_queue_.pop();
  return stream_buffer;
}

bool StreamBufferManager::ReleaseBuffer(uint64_t buffer_id) {
  base::AutoLock l(buffer_manager_lock_);

  auto it = buffer_pointer_map_.find(buffer_id);
  if (it == buffer_pointer_map_.end()) {
    return false;
  }
  buffer_queue_.push(it->second);

  if (notify_callback_) {
    // We run the |notify_callback_| on a separate thread because it's likely
    // the caller would try to allocate buffer from StreamBufferManager, causing
    // deadlock on |buffer_manager_lock_|.
    callback_thread_.task_runner()->PostTask(FROM_HERE,
                                             std::move(notify_callback_));
  }
  return true;
}

mojom::CameraBufferHandlePtr* StreamBufferManager::GetBufferHandle(
    uint64_t buffer_id) {
  base::AutoLock l(buffer_manager_lock_);

  auto it = buffer_pointer_map_.find(buffer_id);
  if (it == buffer_pointer_map_.end()) {
    return nullptr;
  }
  return &(*it->second)->buffer_handle;
}

std::vector<base::ScopedFD>* StreamBufferManager::GetFds(uint64_t buffer_id) {
  base::AutoLock l(buffer_manager_lock_);

  auto it = fd_map_.find(buffer_id);
  if (it == fd_map_.end()) {
    return nullptr;
  }
  return &it->second;
}

bool StreamBufferManager::HasFreeBuffers() {
  base::AutoLock l(buffer_manager_lock_);

  return !buffer_queue_.empty();
}

void StreamBufferManager::SetNotifyBufferCallback(
    base::OnceClosure notify_callback) {
  base::AutoLock l(buffer_manager_lock_);

  notify_callback_ = std::move(notify_callback);
}

}  // namespace cros
