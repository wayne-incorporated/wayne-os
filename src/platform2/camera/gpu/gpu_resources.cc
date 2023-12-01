/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "gpu/gpu_resources.h"

#include <iomanip>

#include <base/functional/bind.h>
#include <base/sequence_checker.h>

#include "cros-camera/camera_buffer_utils.h"
#include "cros-camera/device_config.h"
#include "cros-camera/future.h"
#include "gpu/egl/egl_context.h"
#include "gpu/tracing.h"

namespace cros {

namespace {

const char* kGpuResourceDenyList[] = {
    "reven",
};

}  // namespace

GpuResources::GpuResources(const GpuResourcesOptions& options)
    : gpu_thread_(options.name + "Thread"),
      shared_resources_(options.shared_resources) {
  CHECK(gpu_thread_.Start());
}

GpuResources::~GpuResources() {
  DCHECK_CALLED_ON_VALID_SEQUENCE(gpu_thread_sequence);
  gpu_thread_.Stop();
}

// static
bool GpuResources::IsSupported() {
  std::optional<DeviceConfig> device_config = DeviceConfig::Create();
  if (!device_config) {
    LOGF(WARNING) << "Cannot identify device model; disable GPU computing";
    return false;
  }
  for (auto* name : kGpuResourceDenyList) {
    if (device_config->GetModelName() == name) {
      LOGF(WARNING) << "GPU computing disabled on unsupported device "
                    << std::quoted(device_config->GetModelName());
      return false;
    }
  }
  return true;
}

bool GpuResources::Initialize() {
  auto future = Future<bool>::Create(nullptr);
  PostGpuTaskSync(
      FROM_HERE,
      base::BindOnce(&GpuResources::InitializeOnGpuThread,
                     base::Unretained((this)), GetFutureCallback(future)));
  return future->Wait();
}

void GpuResources::InitializeOnGpuThread(base::OnceCallback<void(bool)> cb) {
  DCHECK(gpu_thread_.IsCurrentThread());
  TRACE_GPU();

  if (!egl_context_) {
    EglContextOptions options;
    if (shared_resources_) {
      options.share_context = shared_resources_->egl_context();
    }
    egl_context_ = EglContext::GetSurfacelessContext(options);
    if (!egl_context_->IsValid()) {
      LOGF(ERROR) << "Failed to create EGL context";
      std::move(cb).Run(false);
      return;
    }
  }
  if (!egl_context_->MakeCurrent()) {
    LOGF(ERROR) << "Failed to make EGL context current";
    std::move(cb).Run(false);
    return;
  }

  image_processor_ = std::make_unique<GpuImageProcessor>();
  if (!image_processor_) {
    LOGF(ERROR) << "Failed to create GpuImageProcessor";
    std::move(cb).Run(false);
    return;
  }

  std::move(cb).Run(true);
}

void GpuResources::SetCache(
    const std::string id,
    std::unique_ptr<GpuResources::CacheContainer> container) {
  DCHECK(gpu_thread_.IsCurrentThread());
  TRACE_GPU();

  CHECK_EQ(0, cache_.count(id));
  cache_.emplace(id, std::move(container));
}

void GpuResources::ClearCache(const std::string id) {
  DCHECK(gpu_thread_.IsCurrentThread());
  TRACE_GPU();

  if (cache_.erase(id) == 0) {
    VLOGF(1) << "Cache entry for " << std::quoted(id) << " does not exist";
  }
}

void GpuResources::DumpSharedImage(const SharedImage& image,
                                   base::FilePath output_file_path) {
  DCHECK(gpu_thread_.IsCurrentThread());
  TRACE_GPU();

  if (image.buffer() != nullptr) {
    glFinish();
    if (!WriteBufferIntoFile(image.buffer(), output_file_path)) {
      LOGF(ERROR) << "Failed to dump image buffer";
    }
  } else {
    uint32_t kDumpBufferUsage = GRALLOC_USAGE_SW_WRITE_OFTEN |
                                GRALLOC_USAGE_SW_READ_OFTEN |
                                GRALLOC_USAGE_HW_TEXTURE;
    int image_width = image.texture().width(),
        image_height = image.texture().height();
    if (!dump_buffer_ ||
        (CameraBufferManager::GetWidth(*dump_buffer_) != image_width) ||
        (CameraBufferManager::GetHeight(*dump_buffer_) != image_height)) {
      dump_buffer_ = CameraBufferManager::AllocateScopedBuffer(
          image.texture().width(), image.texture().height(),
          HAL_PIXEL_FORMAT_RGBX_8888, kDumpBufferUsage);
      if (!dump_buffer_) {
        LOGF(ERROR) << "Failed to allocate dump buffer";
        return;
      }
      dump_image_ = SharedImage::CreateFromBuffer(*dump_buffer_,
                                                  Texture2D::Target::kTarget2D);
      if (!dump_image_.texture().IsValid()) {
        LOGF(ERROR) << "Failed to create SharedImage for dump buffer";
        return;
      }
    }
    // Use the gamma correction shader with Gamma == 1.0 to copy the contents
    // from the GPU texture to the DMA-buf.
    image_processor_->ApplyGammaCorrection(1.0f, image.texture(),
                                           dump_image_.texture());
    glFinish();
    if (!WriteBufferIntoFile(*dump_buffer_, output_file_path)) {
      LOGF(ERROR) << "Failed to dump GPU texture";
    }
  }
}

}  // namespace cros
