/*
 * Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_GPU_ALGORITHM_H_
#define CAMERA_COMMON_CAMERA_GPU_ALGORITHM_H_

#include <map>
#include <memory>
#include <vector>

#include <base/memory/unsafe_shared_memory_region.h>
#include <base/posix/eintr_wrapper.h>
#include <base/synchronization/lock.h>
#include <base/threading/thread.h>

#include "cros-camera/camera_algorithm.h"
#include "cros-camera/camera_gpu_algo_header.h"
#include "cros-camera/portrait_cros_wrapper.h"

namespace cros {

class CameraGPUAlgorithm {
 public:
  static CameraGPUAlgorithm* GetInstance();

  int32_t Initialize(const camera_algorithm_callback_ops_t* callback_ops);

  int32_t RegisterBuffer(int buffer_fd);

  void Request(uint32_t req_id,
               const uint8_t req_header[],
               uint32_t size,
               int32_t buffer_handle);

  void DeregisterBuffers(const int32_t buffer_handles[], uint32_t size);

  void Deinitialize();

 private:
  CameraGPUAlgorithm();

  void InitializeOnThread();

  void RequestOnThread(uint32_t req_id,
                       std::vector<uint8_t> req_header,
                       int32_t buffer_handle);

  base::Thread thread_;

  const camera_algorithm_callback_ops_t* callback_ops_;

  creative_camera::PortraitCrosWrapper portrait_processor_;

  bool is_initialized_;

  // Lock to protect the shared memory map
  base::Lock map_lock_;

  // Store shared memory region with fd as the key
  std::map<int32_t, base::UnsafeSharedMemoryRegion> shm_region_map_;
};

}  // namespace cros

#endif  // CAMERA_COMMON_CAMERA_GPU_ALGORITHM_H_
