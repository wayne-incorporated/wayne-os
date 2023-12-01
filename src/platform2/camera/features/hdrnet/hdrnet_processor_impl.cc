/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/hdrnet/hdrnet_processor_impl.h"

#include <algorithm>
#include <string>
#include <utility>

#include <base/files/file_util.h>
#include <base/timer/elapsed_timer.h>
#include <sync/sync.h>

#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_buffer_utils.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "cros-camera/texture_2d_descriptor.h"
#include "cros-camera/tracing.h"
#include "features/hdrnet/tracing.h"
#include "gpu/egl/egl_fence.h"
#include "gpu/shared_image.h"

namespace cros {

// static
std::unique_ptr<HdrNetProcessor> HdrNetProcessorImpl::CreateInstance(
    const camera_metadata_t* static_info,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  return std::make_unique<HdrNetProcessorImpl>(
      static_info, task_runner,
      HdrNetProcessorDeviceAdapter::CreateInstance(static_info, task_runner));
}

HdrNetProcessorImpl::HdrNetProcessorImpl(
    const camera_metadata_t* static_info,
    scoped_refptr<base::SingleThreadTaskRunner> task_runner,
    std::unique_ptr<HdrNetProcessorDeviceAdapter> processor_device_adapter)
    : task_runner_(task_runner),
      processor_device_adapter_(std::move(processor_device_adapter)) {}

bool HdrNetProcessorImpl::Initialize(GpuResources* gpu_resources,
                                     Size input_size,
                                     const std::vector<Size>& output_sizes) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  TRACE_HDRNET();

  gpu_resources_ = gpu_resources;
  CHECK(gpu_resources_);
  CHECK(gpu_resources_->image_processor());

  for (const auto& s : output_sizes) {
    if (s.width > input_size.width || s.height > input_size.height) {
      LOGF(ERROR) << "Output size " << s.ToString()
                  << " has larger dimension than the input size "
                  << input_size.ToString();
      return false;
    }
  }

  if (!processor_device_adapter_->Initialize(gpu_resources, input_size,
                                             output_sizes)) {
    LOGF(ERROR) << "Failed to initialized HdrNetProcessorDeviceAdapter";
    return false;
  }

  return true;
}

void HdrNetProcessorImpl::TearDown() {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HDRNET();

  processor_device_adapter_->TearDown();
}

void HdrNetProcessorImpl::SetOptions(const Options& options) {
  DCHECK(task_runner_->BelongsToCurrentThread());

  if (options.metadata_logger) {
    metadata_logger_ = *options.metadata_logger;
  }
}

bool HdrNetProcessorImpl::WriteRequestParameters(
    Camera3CaptureDescriptor* request) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HDRNET();

  return processor_device_adapter_->WriteRequestParameters(request,
                                                           metadata_logger_);
}

void HdrNetProcessorImpl::ProcessResultMetadata(
    Camera3CaptureDescriptor* result) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HDRNET();

  processor_device_adapter_->ProcessResultMetadata(result, metadata_logger_);
}

base::ScopedFD HdrNetProcessorImpl::Run(
    int frame_number,
    const HdrNetConfig::Options& options,
    const SharedImage& input_yuv,
    base::ScopedFD input_release_fence,
    const std::vector<buffer_handle_t>& output_nv12_buffers,
    HdrnetMetrics* hdrnet_metrics) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  DCHECK(hdrnet_metrics);
  TRACE_HDRNET();

  for (const auto& b : output_nv12_buffers) {
    if (CameraBufferManager::GetWidth(b) > input_yuv.y_texture().width() ||
        CameraBufferManager::GetHeight(b) > input_yuv.y_texture().height()) {
      LOGF(ERROR) << "Output buffer has larger dimension than the input buffer";
      ++hdrnet_metrics->errors[HdrnetError::kHdrnetProcessorError];
      return base::ScopedFD();
    }
  }

  std::vector<SharedImage> output_images;
  for (const auto& b : output_nv12_buffers) {
    SharedImage output_nv12 =
        SharedImage::CreateFromBuffer(b, Texture2D::Target::kTarget2D,
                                      /*separate_yuv_textures=*/true);
    if (!output_nv12.y_texture().IsValid() ||
        !output_nv12.uv_texture().IsValid()) {
      LOGF(ERROR) << "Failed to create Y/UV texture for the output buffer";
      // TODO(jcliang): We should probably find a way to return a result error
      // here.
      ++hdrnet_metrics->errors[HdrnetError::kHdrnetProcessorError];
      continue;
    }
    output_images.emplace_back(std::move(output_nv12));
  }

  if (input_release_fence.is_valid()) {
    if (sync_wait(input_release_fence.get(), 300)) {
      ++hdrnet_metrics->errors[HdrnetError::kSyncWaitError];
    }
  }

  if (!options.hdrnet_enable) {
    // Convert to NV12 directly.
    for (const auto& output_nv12 : output_images) {
      YUVToNV12(input_yuv, output_nv12);
    }
  } else {
    bool success = false;
    do {
      if (options.dump_buffer) {
        CameraBufferManager* buf_mgr = CameraBufferManager::GetInstance();
        do {
          if (buf_mgr->Register(input_yuv.buffer()) != 0) {
            LOGF(ERROR) << "Failed to register input YUV buffer";
            break;
          }
          if (!WriteBufferIntoFile(
                  input_yuv.buffer(),
                  base::FilePath(base::StringPrintf(
                      "input_yuv_%dx%d_result#%d.yuv",
                      CameraBufferManager::GetWidth(input_yuv.buffer()),
                      CameraBufferManager::GetHeight(input_yuv.buffer()),
                      frame_number)))) {
            LOGF(ERROR) << "Failed to dump input YUV buffer";
          }
          buf_mgr->Deregister(input_yuv.buffer());
        } while (false);
      }

      // Render the HDRnet output on the largest buffer and downscale to the
      // other smaller buffers when needed.
      auto largest_img = std::max_element(
          output_images.begin(), output_images.end(),
          [](const SharedImage& a, const SharedImage& b) {
            return a.y_texture().width() > b.y_texture().width();
          });

      {
        TRACE_HDRNET_EVENT(kEventLinearRgbPipeline, "frame_number",
                           frame_number);
        base::ElapsedTimer t;
        success = processor_device_adapter_->Run(
            frame_number, options, input_yuv, *largest_img, hdrnet_metrics);
        hdrnet_metrics->accumulated_rgb_pipeline_latency_us +=
            t.Elapsed().InMicroseconds();
      }
      if (!success) {
        LOGF(ERROR) << "Failed to run HDRnet pipeline";
        ++hdrnet_metrics->errors[HdrnetError::kRgbPipelineError];
        break;
      }
      if (options.dump_buffer) {
        gpu_resources_->DumpSharedImage(
            *largest_img,
            base::FilePath(base::StringPrintf(
                "hdrnet_pipeline_out_nv12_%dx%d_result#%d.yuv",
                largest_img->y_texture().width(),
                largest_img->y_texture().height(), frame_number)));
      }

      for (auto& output_nv12 : output_images) {
        if (&(*largest_img) == &output_nv12) {
          continue;
        }

        // Here we assume all the streams have the same aspect ratio, so no
        // cropping is done.
        {
          TRACE_HDRNET_EVENT(kEventPostprocess, "frame_number", frame_number);
          base::ElapsedTimer t;
          success = YUVToNV12(*largest_img, output_nv12);
          hdrnet_metrics->accumulated_postprocessing_latency_us +=
              t.Elapsed().InMicroseconds();
        }
        if (!success) {
          LOGF(ERROR) << "Failed to post-process HDRnet pipeline output";
          ++hdrnet_metrics->errors[HdrnetError::kPostprocessingError];
          break;
        }
        if (options.dump_buffer) {
          glFinish();
          CameraBufferManager* buf_mgr = CameraBufferManager::GetInstance();
          do {
            if (buf_mgr->Register(output_nv12.buffer()) != 0) {
              LOGF(ERROR) << "Failed to register output NV12 buffer";
              break;
            }
            if (!WriteBufferIntoFile(
                    output_nv12.buffer(),
                    base::FilePath(base::StringPrintf(
                        "postprocess_out_nv12_%dx%d_result#%d.yuv",
                        CameraBufferManager::GetWidth(output_nv12.buffer()),
                        CameraBufferManager::GetHeight(output_nv12.buffer()),
                        frame_number)))) {
              LOGF(ERROR) << "Failed to dump output NV12 buffer";
            }
            buf_mgr->Deregister(output_nv12.buffer());
          } while (false);
        }
      }
    } while (false);

    ++hdrnet_metrics->num_frames_processed;
    if (!success) {
      for (const auto& output_nv12 : output_images) {
        YUVToNV12(input_yuv, output_nv12);
      }
    }
  }
  {
    TRACE_HDRNET_EVENT("HdrNetProcessorImpl::CreateFence");
    EglFence fence;
    return fence.GetNativeFd();
  }
}

bool HdrNetProcessorImpl::YUVToNV12(const SharedImage& input_yuv,
                                    const SharedImage& output_nv12) {
  DCHECK(task_runner_->BelongsToCurrentThread());
  TRACE_HDRNET();

  bool result = gpu_resources_->image_processor()->YUVToYUV(
      input_yuv.y_texture(), input_yuv.uv_texture(), output_nv12.y_texture(),
      output_nv12.uv_texture());
  if (!result) {
    VLOGF(1) << "Failed to produce NV12 output";
  }
  return result;
}

Texture2DDescriptor CreateTextureInfo(const SharedImage& image) {
  return Texture2DDescriptor{
      .id = base::checked_cast<GLint>(image.texture().handle()),
      .internal_format = GL_RGBA16F,
      .width = image.texture().width(),
      .height = image.texture().height()};
}

}  // namespace cros
