/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_GPU_GPU_RESOURCES_H_
#define CAMERA_GPU_GPU_RESOURCES_H_

#include <map>
#include <memory>
#include <string>
#include <utility>

#include <hardware/gralloc.h>

#include <base/location.h>
#include <base/memory/scoped_refptr.h>
#include <base/sequence_checker.h>
#include <base/task/single_thread_task_runner.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_thread.h"
#include "cros-camera/export.h"
#include "gpu/egl/egl_context.h"
#include "gpu/image_processor.h"
#include "gpu/shared_image.h"
// The tracing macros from perfetto_sdk and libchrome clashes when building
// some test packages.
//
// TODO(jcliang): Enable the trace event once b/244257898 is fixed.
// #include "gpu/tracing.h"

namespace cros {

class GpuResources;

struct GpuResourcesOptions {
  // The name of the GpuResources instance.
  std::string name = "GpuResources";

  // The GpuResources instance to share resources with.
  GpuResources* shared_resources = nullptr;
};

// GpuResources holds the resources required to perform GPU operations. A
// GpuResources instance manages a GPU thread and the context running on the
// thread. There's only one GpuResources instance in the whole camera process.
// It's guaranteed that the GpuResources is created before we load the camera
// HAL adapter, and is destroyed only after the HAL adapter is destroyed.
//
// Processing blocks in the camera service can run GPU operations using the
// PostGpuTask*() helpers. By sharing the GPU context and running on the same
// thread, the different processing blocks can share GPU resources like textures
// and shader programs.
//
// The GetCache() and SetCache() allow a processing block to preserve states
// across different camera sessions. For example, some GL processing pipeline
// running ML models can take several hundreds of ms to initialize. It's
// desirable to create the pipeline once and reuse it across different camera
// device sessions.
class CROS_CAMERA_EXPORT GpuResources {
 public:
  // A user can extend the CacheContainer class to store the data they want and
  // use GetCache()/SetCache() to fetch/store the cached data.
  class CacheContainer {
   public:
    virtual ~CacheContainer() = default;
  };

  explicit GpuResources(
      const GpuResourcesOptions& options = GpuResourcesOptions());
  ~GpuResources();

  // Disallow copy, assign and move since there should be only one instance of
  // GpuResources in the process.
  GpuResources(GpuResources&) = delete;
  GpuResources& operator=(GpuResources&) = delete;
  GpuResources(GpuResources&&) = delete;
  GpuResources& operator=(GpuResources&&) = delete;

  [[nodiscard]] static bool IsSupported();

  [[nodiscard]] bool Initialize();

  template <typename T>
  int PostGpuTask(const base::Location& from_here,
                  base::OnceCallback<T()> task) {
    return gpu_thread_.PostTaskAsync(from_here, std::move(task));
  }

  template <typename T>
  int PostGpuTaskSync(const base::Location& from_here,
                      base::OnceCallback<T()> task,
                      T* result) {
    return gpu_thread_.PostTaskSync(from_here, std::move(task), result);
  }

  int PostGpuTaskSync(const base::Location& from_here, base::OnceClosure task) {
    return gpu_thread_.PostTaskSync(from_here, std::move(task));
  }

  scoped_refptr<base::SingleThreadTaskRunner> gpu_task_runner() const {
    return gpu_thread_.task_runner();
  }

  const EglContext* egl_context() const { return egl_context_.get(); }

  // All the methods below need to run on |gpu_thread_|.

  // Gets and sets a cache entry keyed by |id|.
  template <typename T>
  T* GetCache(const std::string id) {
    DCHECK(gpu_thread_.IsCurrentThread());
    // The tracing macros from perfetto_sdk and libchrome clashes when building
    // some test packages.
    //
    // TODO(jcliang): Enable the trace event once b/244257898 is fixed.
    // TRACE_GPU();

    if (cache_.count(id) == 1) {
      return reinterpret_cast<T*>(cache_.at(id).get());
    }
    return nullptr;
  }

  void SetCache(const std::string id,
                std::unique_ptr<CacheContainer> container);
  void ClearCache(const std::string id);

  // Returns a GpuImageProcessor instance pre-allocated by the GpuResources
  // instance.
  GpuImageProcessor* image_processor() const {
    DCHECK(gpu_thread_.IsCurrentThread());
    return image_processor_.get();
  }

  // Dumps the raw pixel data from shared image |image| to |output_file_path|.
  void DumpSharedImage(const SharedImage& image,
                       base::FilePath output_file_path);

 private:
  void InitializeOnGpuThread(base::OnceCallback<void(bool)> cb);

  CameraThread gpu_thread_;

  GpuResources* shared_resources_ = nullptr;

  // Access to the following members must be sequenced on |gpu_thread_|.
  std::unique_ptr<EglContext> egl_context_;
  std::unique_ptr<GpuImageProcessor> image_processor_;
  std::map<std::string, std::unique_ptr<CacheContainer>> cache_;

  // A buffer that's only allocated when we need to dump the intermediate images
  // for debugging.
  ScopedBufferHandle dump_buffer_ = nullptr;
  SharedImage dump_image_;

  // A sequence checker to verify we start and stop |gpu_thread_| on the same
  // sequence.
  SEQUENCE_CHECKER(gpu_thread_sequence);
};

}  // namespace cros

#endif  // CAMERA_GPU_GPU_RESOURCES_H_
