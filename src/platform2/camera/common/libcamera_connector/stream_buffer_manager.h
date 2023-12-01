/*
 * Copyright 2020 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_LIBCAMERA_CONNECTOR_STREAM_BUFFER_MANAGER_H_
#define CAMERA_COMMON_LIBCAMERA_CONNECTOR_STREAM_BUFFER_MANAGER_H_

#include <map>
#include <queue>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/functional/callback.h>
#include <base/synchronization/lock.h>
#include <base/threading/thread.h>

#include "camera/mojo/camera3.mojom.h"

namespace cros {

// StreamBufferManager is a helper class that manages a set of pre-allocated
// mojom::Camera3StreamBufferPtr from
// CameraDeviceAdapter::ConfigureStreamsAndGetAllocatedBuffers(). The lifetimes
// of these buffers are managed by CameraDeviceAdapter - created during stream
// configuration and released when the device is closed. StreamBufferManager's
// lifetime lasts the entire lifetime of the user intending to use the camera.
// The class can be initialized multiple times when a new stream is configured.
class StreamBufferManager {
 public:
  StreamBufferManager();

  StreamBufferManager(const StreamBufferManager&) = delete;
  StreamBufferManager& operator=(const StreamBufferManager&) = delete;

  ~StreamBufferManager();

  // Initializes StreamBufferManager with a set of pre-allocated buffers.
  // StreamBufferManager can be initialized multiple times with new sets of
  // buffers. The lifetimes of these buffers are managed by camera HAL adapter.
  void Init(std::vector<mojom::Camera3StreamBufferPtr> allocated_buffers);

  // Allocates a free buffer from |buffer_queue_|. If |buffer_queue_| is empty,
  // a null mojom::Camera3StreamBufferPtr is returned.
  mojom::Camera3StreamBufferPtr AllocateBuffer();

  // Releases a used buffer back into the buffer pool. Returns true if the
  // buffer came from the pre-allocated buffers, false otherwise.
  bool ReleaseBuffer(uint64_t buffer_id);

  // Returns the camera buffer handle whose buffer id is |buffer_id|.
  mojom::CameraBufferHandlePtr* GetBufferHandle(uint64_t buffer_id);

  // Returns the file descriptors associated with |buffer_id|.
  std::vector<base::ScopedFD>* GetFds(uint64_t buffer_id);

  // Returns true if StreamBufferManager still has free buffers. It is not
  // guaranteed that AllocateBuffer() would succeed afterwards, since other
  // threads could potentially get a free buffer allocated before that
  bool HasFreeBuffers();

  // Sets the callback that would be triggered once when a free buffer is
  // available.
  void SetNotifyBufferCallback(base::OnceClosure notify_callback);

 private:
  std::vector<mojom::Camera3StreamBufferPtr> buffers_;
  std::queue<mojom::Camera3StreamBufferPtr*> buffer_queue_;
  std::map<uint64_t, mojom::Camera3StreamBufferPtr*> buffer_pointer_map_;
  std::map<uint64_t, std::vector<base::ScopedFD>> fd_map_;
  base::Lock buffer_manager_lock_;

  base::Thread callback_thread_;
  base::OnceClosure notify_callback_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_LIBCAMERA_CONNECTOR_STREAM_BUFFER_MANAGER_H_
