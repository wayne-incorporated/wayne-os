/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/hdrnet/hdrnet_stream_manipulator.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <base/containers/lru_cache.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <cros-camera/spatiotemporal_denoiser.h>
#include <sync/sync.h>
#include <system/camera_metadata.h>

#include "common/camera_hal3_helpers.h"
#include "common/still_capture_processor_impl.h"
#include "common/stream_manipulator.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "cros-camera/texture_2d_descriptor.h"
#include "cros-camera/tracing.h"
#include "features/hdrnet/hdrnet_config.h"
#include "features/hdrnet/hdrnet_processor_impl.h"
#include "features/hdrnet/tracing.h"
#include "gpu/egl/egl_fence.h"
#include "gpu/egl/utils.h"
#include "gpu/gles/texture_2d.h"
#include "gpu/gles/utils.h"
#include "gpu/gpu_resources.h"

namespace cros {

namespace {

constexpr int kDefaultSyncWaitTimeoutMs = 300;

constexpr char kMetadataDumpPath[] = "/run/camera/hdrnet_frame_metadata.json";

constexpr char kLogFrameMetadata[] = "log_frame_metadata";

constexpr char kDenoiserEnable[] = "denoiser_enable";
constexpr char kDenoiserIirTemporalConvergence[] =
    "denoiser_iir_temporal_convergence";
constexpr char kDenoiserNumSpatialPasses[] = "num_spatial_passes";
constexpr char kDenoiserSpatialStrength[] = "spatial_strength";

// Allocate one buffer for denoiser because we run the denoiser in IIR filter
// mode. We'll need to have more buffers if we run the burst denoising mode.
constexpr int kMaxDenoiserBurstLength = 1;

// Used for caching the persistent HDRnet GpuResources instance across camera
// sessions in the root GpuResources instance.
class CachedHdrNetGpuResources : public GpuResources::CacheContainer {
 public:
  constexpr static char kCachedHdrNetGpuResourcesId[] =
      "hdrnet.hdrnet_gpu_resources";

  CachedHdrNetGpuResources() = default;
  ~CachedHdrNetGpuResources() override = default;

  GpuResources* GetHdrNetGpuResources() const {
    return hdrnet_gpu_resources_.get();
  }

  void CreateHdrNetGpuResources(GpuResources* root_gpu_resources) {
    hdrnet_gpu_resources_ = std::make_unique<GpuResources>(GpuResourcesOptions{
        .name = "HdrNetGpuResources", .shared_resources = root_gpu_resources});
    CHECK(hdrnet_gpu_resources_->Initialize());
  }

 private:
  std::unique_ptr<GpuResources> hdrnet_gpu_resources_;
};

// Used for caching the pipeline resources across camera sessions in the
// persistent HDRnet GpuResources instance.
class CachedPipelineResources : public GpuResources::CacheContainer {
 public:
  constexpr static char kCachedPipelineResourcesId[] = "hdrnet.cached_pipeline";
  constexpr static size_t kMaxCacheSize = 5;

  CachedPipelineResources()
      : processors_(kMaxCacheSize), denoisers_(kMaxCacheSize) {}

  ~CachedPipelineResources() override = default;

  // HDRnet processor is stateless. Its internal buffers are initialized
  // according to the input image size. We can cache, share and reuse the HDRnet
  // processor of the same size across different streams or device sessions.
  HdrNetProcessor* GetProcessor(const Size& input_size) {
    auto it = processors_.Get(input_size);
    if (it == processors_.end()) {
      return nullptr;
    }
    return it->second.get();
  }

  void PutProcessor(const Size input_size,
                    std::unique_ptr<HdrNetProcessor> processor) {
    DCHECK(processors_.Peek(input_size) == processors_.end());
    processors_.Put(input_size, std::move(processor));
  }

  // The Spatiotemporal denoiser initializes its internal buffers according to
  // the size of the input image. The internal IIR filter is stateful, but as
  // long as we reset the IIR filter every time we start a new stream, we can
  // cache and reuse the denoisers.
  //
  // TODO(jcliang): We might need to separate the denoisers of two streams with
  // the same resolution for some use-caes.
  SpatiotemporalDenoiser* GetDenoiser(const Size& input_size) {
    auto it = denoisers_.Get(input_size);
    if (it == denoisers_.end()) {
      return nullptr;
    }
    return it->second.get();
  }

  void PutDenoiser(const Size input_size,
                   std::unique_ptr<SpatiotemporalDenoiser> denoiser) {
    DCHECK(denoisers_.Peek(input_size) == denoisers_.end());
    denoisers_.Put(input_size, std::move(denoiser));
  }

 private:
  base::HashingLRUCache<Size, std::unique_ptr<HdrNetProcessor>> processors_;
  base::HashingLRUCache<Size, std::unique_ptr<SpatiotemporalDenoiser>>
      denoisers_;
};

}  // namespace

//
// HdrNetStreamManipulator::HdrNetStreamContext implementations.
//

std::optional<int> HdrNetStreamManipulator::HdrNetStreamContext::PopBuffer() {
  if (usable_buffer_list.empty()) {
    LOGF(ERROR) << "Buffer underrun";
    return std::nullopt;
  }
  HdrNetStreamContext::UsableBufferInfo buffer_info =
      std::move(usable_buffer_list.front());
  usable_buffer_list.pop();
  if (buffer_info.acquire_fence.is_valid() &&
      sync_wait(buffer_info.acquire_fence.get(), kDefaultSyncWaitTimeoutMs) !=
          0) {
    LOGF(WARNING) << "sync_wait timeout on acquiring usable HDRnet buffer";
    NOTREACHED();
  }
  return buffer_info.index;
}

void HdrNetStreamManipulator::HdrNetStreamContext::PushBuffer(
    int index, base::ScopedFD acquire_fence) {
  usable_buffer_list.push(
      {.index = index, .acquire_fence = std::move(acquire_fence)});
}

//
// HdrNetStreamManipulator::HdrNetRequestBufferInfo implementations.
//

HdrNetStreamManipulator::HdrNetRequestBufferInfo::HdrNetRequestBufferInfo(
    HdrNetStreamManipulator::HdrNetStreamContext* context,
    std::vector<camera3_stream_buffer_t>&& buffers)
    : stream_context(context),
      client_requested_yuv_buffers(std::move(buffers)) {}

HdrNetStreamManipulator::HdrNetRequestBufferInfo::HdrNetRequestBufferInfo(
    HdrNetStreamManipulator::HdrNetRequestBufferInfo&& other) {
  *this = std::move(other);
}

HdrNetStreamManipulator::HdrNetRequestBufferInfo&
HdrNetStreamManipulator::HdrNetRequestBufferInfo::operator=(
    HdrNetStreamManipulator::HdrNetRequestBufferInfo&& other) {
  if (this != &other) {
    Invalidate();
    stream_context = other.stream_context;
    buffer_index = other.buffer_index;
    other.buffer_index = kInvalidBufferIndex;
    release_fence = std::move(other.release_fence);
    client_requested_yuv_buffers.swap(other.client_requested_yuv_buffers);
    blob_result_pending = other.blob_result_pending;
    blob_intermediate_yuv_pending = other.blob_intermediate_yuv_pending;
    skip_hdrnet_processing = other.skip_hdrnet_processing;
    other.Invalidate();
  }
  return *this;
}

HdrNetStreamManipulator::HdrNetRequestBufferInfo::~HdrNetRequestBufferInfo() {
  Invalidate();
}

void HdrNetStreamManipulator::HdrNetRequestBufferInfo::Invalidate() {
  if (stream_context && buffer_index != kInvalidBufferIndex) {
    stream_context->PushBuffer(buffer_index, std::move(release_fence));
  }
  stream_context = nullptr;
  buffer_index = kInvalidBufferIndex;
  release_fence.reset();
  client_requested_yuv_buffers.clear();
  blob_result_pending = false;
  blob_intermediate_yuv_pending = false;
  skip_hdrnet_processing = false;
}

//
// HdrNetStreamManipulator implementations.
//

HdrNetStreamManipulator::HdrNetStreamManipulator(
    GpuResources* root_gpu_resources,
    base::FilePath config_file_path,
    std::unique_ptr<StillCaptureProcessor> still_capture_processor,
    HdrNetProcessor::Factory hdrnet_processor_factory,
    HdrNetConfig::Options* options)
    : root_gpu_resources_(root_gpu_resources),
      hdrnet_processor_factory_(
          !hdrnet_processor_factory.is_null()
              ? std::move(hdrnet_processor_factory)
              : base::BindRepeating(HdrNetProcessorImpl::CreateInstance)),
      config_(ReloadableConfigFile::Options{
          config_file_path,
          base::FilePath(HdrNetConfig::kOverrideHdrNetConfigFile)}),
      still_capture_processor_(std::move(still_capture_processor)),
      camera_metrics_(CameraMetrics::New()),
      metadata_logger_({.dump_path = base::FilePath(kMetadataDumpPath)}) {
  DCHECK(root_gpu_resources_);
  root_gpu_resources_->PostGpuTaskSync(
      FROM_HERE,
      base::BindOnce(
          &HdrNetStreamManipulator::InitializeGpuResourcesOnRootGpuThread,
          base::Unretained(this)));
  CHECK_NE(hdrnet_gpu_resources_, nullptr);

  if (!config_.IsValid()) {
    if (options) {
      // Options for testing.
      options_ = *options;
    } else {
      LOGF(ERROR) << "Cannot load valid config; turn off feature by default";
      options_.hdrnet_enable = false;
    }
  }
  config_.SetCallback(base::BindRepeating(
      &HdrNetStreamManipulator::OnOptionsUpdated, base::Unretained(this)));
}

HdrNetStreamManipulator::~HdrNetStreamManipulator() {
  hdrnet_gpu_resources_->PostGpuTaskSync(
      FROM_HERE, base::BindOnce(&HdrNetStreamManipulator::ResetStateOnGpuThread,
                                base::Unretained(this)));
}

bool HdrNetStreamManipulator::Initialize(
    const camera_metadata_t* static_info,
    StreamManipulator::Callbacks callbacks) {
  DCHECK(hdrnet_gpu_resources_);

  bool ret;
  hdrnet_gpu_resources_->PostGpuTaskSync(
      FROM_HERE,
      base::BindOnce(&HdrNetStreamManipulator::InitializeOnGpuThread,
                     base::Unretained(this), base::Unretained(static_info),
                     std::move(callbacks)),
      &ret);
  return ret;
}

bool HdrNetStreamManipulator::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effects_map) {
  DCHECK(hdrnet_gpu_resources_);

  bool ret;
  hdrnet_gpu_resources_->PostGpuTaskSync(
      FROM_HERE,
      base::BindOnce(&HdrNetStreamManipulator::ConfigureStreamsOnGpuThread,
                     base::Unretained(this), base::Unretained(stream_config)),
      &ret);
  return ret;
}

bool HdrNetStreamManipulator::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  DCHECK(hdrnet_gpu_resources_);

  bool ret;
  hdrnet_gpu_resources_->PostGpuTaskSync(
      FROM_HERE,
      base::BindOnce(&HdrNetStreamManipulator::OnConfiguredStreamsOnGpuThread,
                     base::Unretained(this), base::Unretained(stream_config)),
      &ret);
  return ret;
}

bool HdrNetStreamManipulator::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  return true;
}

bool HdrNetStreamManipulator::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  DCHECK(hdrnet_gpu_resources_);

  bool ret;
  hdrnet_gpu_resources_->PostGpuTaskSync(
      FROM_HERE,
      base::BindOnce(&HdrNetStreamManipulator::ProcessCaptureRequestOnGpuThread,
                     base::Unretained(this), base::Unretained(request)),
      &ret);
  return ret;
}

bool HdrNetStreamManipulator::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  DCHECK(hdrnet_gpu_resources_);

  hdrnet_gpu_resources_->PostGpuTask(
      FROM_HERE,
      base::BindOnce(&HdrNetStreamManipulator::ProcessCaptureResultOnGpuThread,
                     base::Unretained(this), std::move(result)));
  return true;
}

void HdrNetStreamManipulator::Notify(camera3_notify_msg_t msg) {
  DCHECK(hdrnet_gpu_resources_);

  bool ret;
  hdrnet_gpu_resources_->PostGpuTaskSync(
      FROM_HERE,
      base::BindOnce(&HdrNetStreamManipulator::NotifyOnGpuThread,
                     base::Unretained(this), base::Unretained(&msg)),
      &ret);
  callbacks_.notify_callback.Run(std::move(msg));
}

bool HdrNetStreamManipulator::Flush() {
  DCHECK(hdrnet_gpu_resources_);

  bool ret;
  hdrnet_gpu_resources_->PostGpuTaskSync(
      FROM_HERE,
      base::BindOnce(&HdrNetStreamManipulator::FlushOnGpuThread,
                     base::Unretained(this)),
      &ret);
  return ret;
}

// static
HdrNetStreamManipulator::HdrNetBufferInfoList::iterator
HdrNetStreamManipulator::FindMatchingBufferInfo(
    HdrNetStreamManipulator::HdrNetBufferInfoList* list,
    const HdrNetStreamManipulator::HdrNetStreamContext* const context) {
  auto it = std::find_if(list->begin(), list->end(),
                         [context](const HdrNetRequestBufferInfo& buf_info) {
                           return buf_info.stream_context == context;
                         });
  return it;
}

HdrNetStreamManipulator::HdrNetRequestBufferInfo*
HdrNetStreamManipulator::GetBufferInfoWithPendingBlobStream(
    int frame_number, const camera3_stream_t* blob_stream) {
  auto iter = request_buffer_info_.find(frame_number);
  if (iter == request_buffer_info_.end()) {
    return nullptr;
  }
  for (auto& entry : iter->second) {
    if (entry.blob_result_pending &&
        entry.stream_context->original_stream == blob_stream) {
      return &entry;
    }
  }
  return nullptr;
}

void HdrNetStreamManipulator::InitializeGpuResourcesOnRootGpuThread() {
  DCHECK(root_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());

  CachedHdrNetGpuResources* cache =
      root_gpu_resources_->GetCache<CachedHdrNetGpuResources>(
          CachedHdrNetGpuResources::kCachedHdrNetGpuResourcesId);
  if (!cache) {
    root_gpu_resources_->SetCache(
        CachedHdrNetGpuResources::kCachedHdrNetGpuResourcesId,
        std::make_unique<CachedHdrNetGpuResources>());
    cache = root_gpu_resources_->GetCache<CachedHdrNetGpuResources>(
        CachedHdrNetGpuResources::kCachedHdrNetGpuResourcesId);
  }
  CHECK(cache);

  if (!cache->GetHdrNetGpuResources()) {
    cache->CreateHdrNetGpuResources(root_gpu_resources_);
  }
  hdrnet_gpu_resources_ = cache->GetHdrNetGpuResources();
}

bool HdrNetStreamManipulator::InitializeOnGpuThread(
    const camera_metadata_t* static_info,
    StreamManipulator::Callbacks callbacks) {
  DCHECK(hdrnet_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  TRACE_HDRNET();

  static_info_.acquire(clone_camera_metadata(static_info));
  callbacks_ = std::move(callbacks);
  return true;
}

bool HdrNetStreamManipulator::ConfigureStreamsOnGpuThread(
    Camera3StreamConfiguration* stream_config) {
  DCHECK(hdrnet_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  TRACE_HDRNET([&](perfetto::EventContext ctx) {
    stream_config->PopulateEventAnnotation(ctx);
  });

  // Clear the stream configuration from the previous session.
  ResetStateOnGpuThread();

  if (VLOG_IS_ON(1)) {
    VLOGF(1) << "Before stream manipulation:";
    for (const auto* s : stream_config->GetStreams()) {
      VLOGF(1) << GetDebugString(s);
    }
  }

  base::span<camera3_stream_t* const> client_requested_streams =
      stream_config->GetStreams();
  std::vector<camera3_stream_t*> modified_streams;
  int num_yuv_streams = 0;
  int num_blob_streams = 0;
  for (auto s : client_requested_streams) {
    if (s->stream_type != CAMERA3_STREAM_OUTPUT) {
      // Only output buffers are supported.
      modified_streams.push_back(s);
      continue;
    }

    if (s->format == HAL_PIXEL_FORMAT_YCbCr_420_888 ||
        s->format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED ||
        s->format == HAL_PIXEL_FORMAT_BLOB) {
      if (s->format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED &&
          (s->usage & GRALLOC_USAGE_HW_CAMERA_ZSL) ==
              GRALLOC_USAGE_HW_CAMERA_ZSL) {
        // Ignore ZSL streams.
        modified_streams.push_back(s);
        continue;
      }

      // TODO(jcliang): See if we need to use 10-bit YUV (i.e. with format
      // HAL_PIXEL_FORMAT_YCBCR_P010);
      // TODO(kamesan): Reuse HDRnet stream if there are BLOB and still YUV with
      // the same resolution.
      HdrNetStreamContext* context =
          CreateHdrNetStreamContext(s, HAL_PIXEL_FORMAT_YCbCr_420_888);
      switch (context->mode) {
        case HdrNetStreamContext::Mode::kReplaceYuv:
          // TODO(jcliang): We may need to treat YUV stream with maximum
          // resolution specially and mark it here, since it's what we use in
          // YUV reprocessing.
          modified_streams.push_back(context->hdrnet_stream.get());
          ++num_yuv_streams;
          hdrnet_metrics_.max_yuv_stream_size =
              std::max(static_cast<int>(context->hdrnet_stream->width *
                                        context->hdrnet_stream->height),
                       hdrnet_metrics_.max_yuv_stream_size);
          break;

        case HdrNetStreamContext::Mode::kAppendWithBlob:
          DCHECK_EQ(s->format, HAL_PIXEL_FORMAT_BLOB);
          still_capture_processor_->Initialize(s, callbacks_.result_callback);
          modified_streams.push_back(s);
          modified_streams.push_back(context->hdrnet_stream.get());
          ++num_blob_streams;
          hdrnet_metrics_.max_blob_stream_size =
              std::max(static_cast<int>(context->hdrnet_stream->width *
                                        context->hdrnet_stream->height),
                       hdrnet_metrics_.max_blob_stream_size);
          break;
      }
    }
  }

  stream_config->SetStreams(modified_streams);

  hdrnet_metrics_.num_concurrent_hdrnet_streams = hdrnet_stream_context_.size();
  bool has_different_aspect_ratio = false;
  for (size_t i = 1; i < hdrnet_stream_context_.size(); ++i) {
    const auto* s1 = hdrnet_stream_context_[i - 1]->hdrnet_stream.get();
    const auto* s2 = hdrnet_stream_context_[i]->hdrnet_stream.get();
    if (s1->width * s2->height != s2->width * s1->height) {
      has_different_aspect_ratio = true;
      break;
    }
  }
  if (num_yuv_streams == 1) {
    if (num_blob_streams == 0) {
      hdrnet_metrics_.stream_config =
          HdrnetStreamConfiguration::kSingleYuvStream;
    } else {
      hdrnet_metrics_.stream_config =
          HdrnetStreamConfiguration::kSingleYuvStreamWithBlob;
    }
  } else if (num_yuv_streams > 1) {
    if (num_blob_streams == 0) {
      hdrnet_metrics_.stream_config =
          has_different_aspect_ratio
              ? HdrnetStreamConfiguration::
                    kMultipleYuvStreamsOfDifferentAspectRatio
              : HdrnetStreamConfiguration::kMultipleYuvStreams;
    } else {
      hdrnet_metrics_.stream_config =
          has_different_aspect_ratio
              ? HdrnetStreamConfiguration::
                    kMultipleYuvStreamsOfDifferentAspectRatioWithBlob
              : HdrnetStreamConfiguration::kMultipleYuvStreamsWithBlob;
    }
  }

  if (VLOG_IS_ON(1)) {
    VLOGF(1) << "After stream manipulation:";
    for (const auto* s : stream_config->GetStreams()) {
      VLOGF(1) << GetDebugString(s);
    }
  }

  return true;
}

bool HdrNetStreamManipulator::OnConfiguredStreamsOnGpuThread(
    Camera3StreamConfiguration* stream_config) {
  DCHECK(hdrnet_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  TRACE_HDRNET([&](perfetto::EventContext ctx) {
    stream_config->PopulateEventAnnotation(ctx);
  });

  // Restore HDRnet streams to the original streams.
  if (VLOG_IS_ON(1)) {
    VLOGF(1) << "Before stream manipulation:";
    for (const auto* s : stream_config->GetStreams()) {
      VLOGF(1) << GetDebugString(s);
    }
  }

  base::span<camera3_stream_t* const> modified_streams =
      stream_config->GetStreams();
  std::vector<camera3_stream_t*> restored_streams;
  for (auto* modified_stream : modified_streams) {
    HdrNetStreamContext* context =
        GetHdrNetContextFromHdrNetStream(modified_stream);
    if (!context) {
      // Not a stream that we replaced, so pass to client directly.
      restored_streams.push_back(modified_stream);
      continue;
    }
    switch (context->mode) {
      case HdrNetStreamContext::Mode::kReplaceYuv: {
        // Propagate the fields set by HAL back to the client.
        camera3_stream_t* original_stream = context->original_stream;
        original_stream->max_buffers = modified_stream->max_buffers;
        original_stream->usage = modified_stream->usage;
        original_stream->priv = modified_stream->priv;
        restored_streams.push_back(original_stream);
        break;
      }

      case HdrNetStreamContext::Mode::kAppendWithBlob:
        // Skip the HDRnet stream we added for BLOB.
        break;
    }
  }

  stream_config->SetStreams(restored_streams);

  if (VLOG_IS_ON(1)) {
    VLOGF(1) << "After stream manipulation:";
    for (const auto* s : stream_config->GetStreams()) {
      VLOGF(1) << GetDebugString(s);
    }
  }

  bool success = SetUpPipelineOnGpuThread();
  if (!success) {
    LOGF(ERROR) << "Cannot set up HDRnet pipeline";
    return false;
  }

  return true;
}

bool HdrNetStreamManipulator::ProcessCaptureRequestOnGpuThread(
    Camera3CaptureDescriptor* request) {
  DCHECK(hdrnet_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  TRACE_HDRNET("frame_number", request->frame_number());

  if (VLOG_IS_ON(2)) {
    VLOGFID(2, request->frame_number()) << " Got request:";
    if (request->has_input_buffer()) {
      VLOGF(2) << "\t" << GetDebugString(request->GetInputBuffer()->stream());
    }
    for (const auto& request_buffer : request->GetOutputBuffers()) {
      VLOGF(2) << "\t" << GetDebugString(request_buffer.stream());
    }
  }

  bool skip_hdrnet_processing = false;
  base::span<const uint8_t> tm_mode =
      request->GetMetadata<uint8_t>(ANDROID_TONEMAP_MODE);
  if (!tm_mode.empty() && (tm_mode[0] == ANDROID_TONEMAP_MODE_CONTRAST_CURVE ||
                           tm_mode[0] == ANDROID_TONEMAP_MODE_GAMMA_VALUE ||
                           tm_mode[0] == ANDROID_TONEMAP_MODE_PRESET_CURVE)) {
    skip_hdrnet_processing = true;
  }

  if (request->has_input_buffer()) {
    // Skip reprocessing requests. We can't touch the output buffers of a
    // reprocessing request since they have to be produced from the given input
    // buffer.
    return true;
  }

  for (auto& context : hdrnet_stream_context_) {
    context->processor->SetOptions(
        {.metadata_logger =
             options_.log_frame_metadata ? &metadata_logger_ : nullptr});
  }

  // First, pick the set of HDRnet stream that we will put into the request.
  std::vector<Camera3StreamBuffer> client_output_buffers =
      request->AcquireOutputBuffers();
  HdrNetBufferInfoList hdrnet_buf_to_add;
  for (auto& request_buffer : client_output_buffers) {
    HdrNetStreamContext* stream_context =
        GetHdrNetContextFromRequestedStream(request_buffer.stream());
    if (!stream_context) {
      // Not a stream that we care, so simply pass through to HAL.
      request->AppendOutputBuffer(std::move(request_buffer));
      continue;
    }

    // Only change the metadata when the client request settings is not null.
    // This is mainly to make the CTS tests happy, as some test cases set null
    // settings and if we change that the vendor camera HAL may not handle the
    // incremental changes well.
    if (request->has_metadata()) {
      stream_context->processor->WriteRequestParameters(request);
    }
    switch (stream_context->mode) {
      case HdrNetStreamContext::Mode::kReplaceYuv: {
        auto is_compatible =
            [stream_context](const HdrNetRequestBufferInfo& buf_info) {
              return (buf_info.stream_context->mode ==
                      HdrNetStreamContext::Mode::kReplaceYuv) &&
                     HaveSameAspectRatio(
                         buf_info.stream_context->hdrnet_stream.get(),
                         stream_context->hdrnet_stream.get());
            };
        auto it = std::find_if(hdrnet_buf_to_add.begin(),
                               hdrnet_buf_to_add.end(), is_compatible);
        if (it != hdrnet_buf_to_add.end()) {
          // Request only one stream and produce the other smaller buffers
          // through downscaling. This is more efficient than running HDRnet
          // processor for each buffer.
          if (stream_context->hdrnet_stream->width >
              it->stream_context->hdrnet_stream->width) {
            it->stream_context = stream_context;
          }
          it->client_requested_yuv_buffers.push_back(
              request_buffer.raw_buffer());
        } else {
          HdrNetRequestBufferInfo buf_info(stream_context,
                                           {request_buffer.raw_buffer()});
          buf_info.skip_hdrnet_processing = skip_hdrnet_processing;
          hdrnet_buf_to_add.emplace_back(std::move(buf_info));
        }
        break;
      }

      case HdrNetStreamContext::Mode::kAppendWithBlob: {
        DCHECK_EQ(request_buffer.stream()->format, HAL_PIXEL_FORMAT_BLOB);
        // Defer the final BLOB buffer to the StillCaptureProcessor as we'll be
        // handling the BLOB metadata and YUV buffer asynchronously.
        still_capture_processor_->QueuePendingOutputBuffer(
            request->frame_number(), request_buffer.raw_buffer(), *request);
        // Still queue the BLOB buffer so that we can extract the metadata.
        request->AppendOutputBuffer(std::move(request_buffer));
        // Finally queue the HDRnet YUV buffer that will be used to produce the
        // BLOB image.
        HdrNetRequestBufferInfo buf_info(stream_context, {});
        buf_info.blob_result_pending = true;
        buf_info.blob_intermediate_yuv_pending = true;
        buf_info.skip_hdrnet_processing = skip_hdrnet_processing;
        hdrnet_buf_to_add.emplace_back(std::move(buf_info));
        break;
      }
    }
  }

  // After we have the set of HdrNet streams, allocate the HdrNet buffers for
  // the request.
  for (auto& info : hdrnet_buf_to_add) {
    std::optional<int> buffer_index = info.stream_context->PopBuffer();
    if (!buffer_index) {
      // TODO(jcliang): This is unlikely, but we should report a buffer error in
      // this case.
      return false;
    }
    info.buffer_index = *buffer_index;
    request->AppendOutputBuffer(Camera3StreamBuffer::MakeRequestOutput({
        .stream = info.stream_context->hdrnet_stream.get(),
        .buffer = const_cast<buffer_handle_t*>(
            &info.stream_context->shared_images[*buffer_index].buffer()),
        .status = CAMERA3_BUFFER_STATUS_OK,
        .acquire_fence = -1,
        .release_fence = -1,
    }));
  }

  uint32_t frame_number = request->frame_number();
  request_buffer_info_.insert({frame_number, std::move(hdrnet_buf_to_add)});

  if (VLOG_IS_ON(2)) {
    VLOGFID(2, frame_number) << "Modified request:";
    base::span<const Camera3StreamBuffer> output_buffers =
        request->GetOutputBuffers();
    for (const auto& request_buffer : output_buffers) {
      VLOGF(2) << "\t" << GetDebugString(request_buffer.stream());
    }
  }

  return true;
}

bool HdrNetStreamManipulator::ProcessCaptureResultOnGpuThread(
    Camera3CaptureDescriptor result) {
  DCHECK(hdrnet_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  TRACE_HDRNET("frame_number", result.frame_number());

  if (VLOG_IS_ON(2)) {
    VLOGFID(2, result.frame_number()) << "Got result:";
    if (result.has_input_buffer()) {
      VLOGF(2) << "\t" << GetDebugString(result.GetInputBuffer()->stream());
    }
    for (const auto& hal_result_buffer : result.GetOutputBuffers()) {
      VLOGF(2) << "\t" << GetDebugString(hal_result_buffer.stream());
    }
  }

  auto submit_result_task =
      StreamManipulator::MakeScopedCaptureResultCallbackRunner(
          callbacks_.result_callback, result);

  if (result.has_metadata()) {
    if (options_.hdrnet_enable) {
      // Result metadata may come before the buffers due to partial results.
      for (const auto& context : hdrnet_stream_context_) {
        // TODO(jcliang): Update the LUT textures once and share it with all
        // processors.
        context->processor->ProcessResultMetadata(&result);
      }
    }
  }

  if (result.num_output_buffers() == 0) {
    return true;
  }

  std::vector<Camera3StreamBuffer> hdrnet_buffer_to_process =
      ExtractHdrNetBuffersToProcess(result);

  base::ScopedClosureRunner clean_up(base::BindOnce(
      [](Camera3CaptureDescriptor* result,
         std::map<uint32_t, HdrNetBufferInfoList>& request_buffer_info) {
        // Remove a pending request if the YUV buffers are done rendering and
        // the pending BLOB buffer is received.
        HdrNetBufferInfoList& pending_request_buffers =
            request_buffer_info[result->frame_number()];
        for (auto it = pending_request_buffers.begin();
             it != pending_request_buffers.end();) {
          if (it->client_requested_yuv_buffers.empty() &&
              !it->blob_result_pending && !it->blob_intermediate_yuv_pending) {
            it = pending_request_buffers.erase(it);
          } else {
            ++it;
          }
        }
        if (pending_request_buffers.empty()) {
          VLOGFID(2, result->frame_number())
              << "Done processing all pending buffers";
          request_buffer_info.erase(result->frame_number());
        }

        if (VLOG_IS_ON(2)) {
          VLOGFID(2, result->frame_number()) << "Modified result:";
          base::span<const Camera3StreamBuffer> output_buffers =
              result->GetOutputBuffers();
          for (const auto& buffer : output_buffers) {
            VLOGF(2) << "\t" << GetDebugString(buffer.stream());
          }
        }
      },
      base::Unretained(&result), std::ref(request_buffer_info_)));

  if (hdrnet_buffer_to_process.empty()) {
    return true;
  }

  HdrNetBufferInfoList& pending_request_buffers =
      request_buffer_info_[result.frame_number()];

  // Process each HDRnet buffer in this capture result and produce the client
  // requested output buffers associated with each HDRnet buffer.
  for (auto& hdrnet_buffer : hdrnet_buffer_to_process) {
    TRACE_HDRNET_EVENT("HdrNetStreamManipulator::ProcessHdrnetBuffer",
                       "frame_number", result.frame_number(), "width",
                       hdrnet_buffer.stream()->width, "height",
                       hdrnet_buffer.stream()->height, "format",
                       hdrnet_buffer.stream()->format,
                       perfetto::Flow::ProcessScoped(hdrnet_buffer.flow_id()));
    HdrNetStreamContext* stream_context =
        GetHdrNetContextFromHdrNetStream(hdrnet_buffer.stream());
    auto request_buffer_info =
        FindMatchingBufferInfo(&pending_request_buffers, stream_context);
    DCHECK(request_buffer_info != pending_request_buffers.end());

    if (options_.denoiser_enable) {
      TRACE_HDRNET_EVENT(
          "HdrNetStreamManipulator::RunIirDenoise",
          perfetto::Flow::ProcessScoped(hdrnet_buffer.flow_id()));
      // Run the denoiser.
      SharedImage& input_img =
          stream_context->shared_images[request_buffer_info->buffer_index];
      Texture2DDescriptor input_luma = {
          .id = static_cast<GLint>(input_img.y_texture().handle()),
          .internal_format = input_img.y_texture().internal_format(),
          .width = input_img.y_texture().width(),
          .height = input_img.y_texture().height(),
      };
      Texture2DDescriptor input_chroma = {
          .id = static_cast<GLint>(input_img.uv_texture().handle()),
          .internal_format = input_img.uv_texture().internal_format(),
          .width = input_img.uv_texture().width(),
          .height = input_img.uv_texture().height(),
      };

      SharedImage& output_img = stream_context->denoiser_intermediate;
      Texture2DDescriptor output_luma = {
          .id = static_cast<GLint>(output_img.y_texture().handle()),
          .internal_format = output_img.y_texture().internal_format(),
          .width = output_img.y_texture().width(),
          .height = output_img.y_texture().height(),
      };
      Texture2DDescriptor output_chroma = {
          .id = static_cast<GLint>(output_img.uv_texture().handle()),
          .internal_format = output_img.uv_texture().internal_format(),
          .width = output_img.uv_texture().width(),
          .height = output_img.uv_texture().height(),
      };
      stream_context->denoiser->RunIirDenoise(
          input_luma, input_chroma, output_luma, output_chroma,
          {.iir_temporal_convergence = options_.iir_temporal_convergence,
           .spatial_strength = options_.spatial_strength,
           .num_spatial_passes = options_.num_spatial_passes,
           .reset_temporal_buffer =
               stream_context->should_reset_temporal_buffer});
      if (stream_context->should_reset_temporal_buffer) {
        stream_context->should_reset_temporal_buffer = false;
      }
    }

    std::vector<buffer_handle_t> buffers_to_render;
    if (!GetBuffersToRender(stream_context, &(*request_buffer_info),
                            &buffers_to_render)) {
      return false;
    }

    // Run the HDRNet pipeline and write to the buffers.
    HdrNetConfig::Options processor_config =
        PrepareProcessorConfig(&result, *request_buffer_info);
    const SharedImage& image =
        options_.denoiser_enable
            ? stream_context->denoiser_intermediate
            : stream_context->shared_images[request_buffer_info->buffer_index];
    request_buffer_info->release_fence = stream_context->processor->Run(
        result.frame_number(), processor_config, image,
        base::ScopedFD(hdrnet_buffer.take_release_fence()), buffers_to_render,
        &hdrnet_metrics_);

    OnBuffersRendered(result, stream_context, &(*request_buffer_info));
  }

  return true;
}

bool HdrNetStreamManipulator::NotifyOnGpuThread(camera3_notify_msg_t* msg) {
  DCHECK(hdrnet_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  TRACE_HDRNET();
  // Free up buffers in case of error.

  if (msg->type == CAMERA3_MSG_ERROR) {
    camera3_error_msg_t& error = msg->message.error;
    VLOGFID(1, error.frame_number) << "Got error notify:"
                                   << " stream=" << error.error_stream
                                   << " errorcode=" << error.error_code;
    HdrNetStreamContext* stream_context =
        GetHdrNetContextFromHdrNetStream(error.error_stream);
    switch (error.error_code) {
      case CAMERA3_MSG_ERROR_DEVICE:
        // Nothing we can do here. Simply restore the stream and forward the
        // error.
      case CAMERA3_MSG_ERROR_RESULT:
        // Result metadata may not be available. We can still produce the
        // processed frame using metadata from previous frame.
        break;

      case CAMERA3_MSG_ERROR_REQUEST:
        // There will be no capture result, so simply destroy the associated
        // RequestContext to free the HdrNet buffers.
        if (request_buffer_info_.count(error.frame_number) == 0) {
          break;
        }
        request_buffer_info_.erase(error.frame_number);
        break;

      case CAMERA3_MSG_ERROR_BUFFER: {
        // The result buffer will not be available, so recycle the hdrnet
        // buffer.
        if (request_buffer_info_.count(error.frame_number) == 0) {
          break;
        }
        HdrNetBufferInfoList& buf_info =
            request_buffer_info_[error.frame_number];
        auto it = FindMatchingBufferInfo(&buf_info, stream_context);
        if (it != buf_info.end()) {
          buf_info.erase(it);
        }
        if (buf_info.empty()) {
          request_buffer_info_.erase(error.frame_number);
        }
        break;
      }
    }

    // Restore the original stream so the message makes sense to the client.
    if (stream_context) {
      error.error_stream = stream_context->original_stream;
    }

    ++hdrnet_metrics_.errors[HdrnetError::kCameraHal3Error];
  }

  return true;
}

bool HdrNetStreamManipulator::FlushOnGpuThread() {
  DCHECK(hdrnet_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  TRACE_HDRNET();

  return true;
}

std::vector<Camera3StreamBuffer>
HdrNetStreamManipulator::ExtractHdrNetBuffersToProcess(
    Camera3CaptureDescriptor& result) {
  std::vector<Camera3StreamBuffer> hdrnet_buffer_to_process;

  for (auto& hal_result_buffer : result.AcquireOutputBuffers()) {
    HdrNetStreamContext* hdrnet_stream_context =
        GetHdrNetContextFromHdrNetStream(hal_result_buffer.stream());
    if (hdrnet_stream_context) {
      hdrnet_buffer_to_process.push_back(std::move(hal_result_buffer));
      continue;
    }

    // The buffer is not a HDRnet buffer we added, but it may be a BLOB
    // buffer that a kAppendWithBlob HDRnet stream is associated with.
    if (hal_result_buffer.stream()->format == HAL_PIXEL_FORMAT_BLOB) {
      HdrNetStreamContext* associated_stream_context =
          GetHdrNetContextFromRequestedStream(hal_result_buffer.stream());
      HdrNetRequestBufferInfo* request_info =
          GetBufferInfoWithPendingBlobStream(result.frame_number(),
                                             hal_result_buffer.stream());
      if (associated_stream_context && request_info) {
        DCHECK_EQ(associated_stream_context->mode,
                  HdrNetStreamContext::Mode::kAppendWithBlob);
        still_capture_processor_->QueuePendingAppsSegments(
            result.frame_number(), *hal_result_buffer.buffer(),
            base::ScopedFD(hal_result_buffer.take_release_fence()));
        request_info->blob_result_pending = false;
        continue;
      }
    }

    // Not a buffer that we added or depend on, so pass to the client
    // directly.
    result.AppendOutputBuffer(std::move(hal_result_buffer));
  }

  return hdrnet_buffer_to_process;
}

bool HdrNetStreamManipulator::GetBuffersToRender(
    HdrNetStreamContext* stream_context,
    HdrNetRequestBufferInfo* request_buffer_info,
    std::vector<buffer_handle_t>* buffers_to_write) {
  DCHECK(stream_context);
  DCHECK(request_buffer_info);
  DCHECK(buffers_to_write);
  switch (stream_context->mode) {
    case HdrNetStreamContext::Mode::kReplaceYuv:
      // For normal YUV buffers: HDRnet pipeline writes to the client output
      // buffers directly. All the buffers in |request_buffer_info| having the
      // same aspect ratio as |stream_context| can be rendered in the same
      // batch.
      for (auto& requested_buffer :
           request_buffer_info->client_requested_yuv_buffers) {
        if (!HaveSameAspectRatio(stream_context->hdrnet_stream.get(),
                                 requested_buffer.stream)) {
          continue;
        }
        if (requested_buffer.acquire_fence != -1) {
          if (sync_wait(requested_buffer.acquire_fence,
                        kDefaultSyncWaitTimeoutMs) != 0) {
            LOGF(WARNING) << "sync_wait timeout on acquiring requested buffer";
            // TODO(jcliang): We should trigger a notify message of
            // buffer error here.
            ++hdrnet_metrics_.errors[HdrnetError::kSyncWaitError];
            return false;
          }
          close(requested_buffer.acquire_fence);
          requested_buffer.acquire_fence = -1;
        }
        buffers_to_write->push_back(*requested_buffer.buffer);
      }
      hdrnet_metrics_.max_output_buffers_rendered =
          std::max(static_cast<int>(buffers_to_write->size()),
                   hdrnet_metrics_.max_output_buffers_rendered);
      break;

    case HdrNetStreamContext::Mode::kAppendWithBlob:
      // For BLOB buffers: HDRnet writes to the intermediate buffer,
      // which will then be encoded into the JPEG image client
      // requested.
      buffers_to_write->push_back(*stream_context->still_capture_intermediate);
      ++hdrnet_metrics_.num_still_shot_taken;
      break;
  }
  return true;
}

HdrNetConfig::Options HdrNetStreamManipulator::PrepareProcessorConfig(
    Camera3CaptureDescriptor* result,
    const HdrNetRequestBufferInfo& buf_info) const {
  // Run the HDRNet pipeline and write to the buffers.
  HdrNetConfig::Options run_options = options_;

  // Use the HDR ratio calculated by Gcam AE if available.
  std::optional<float> gcam_ae_hdr_ratio = result->feature_metadata().hdr_ratio;
  if (gcam_ae_hdr_ratio) {
    run_options.hdr_ratio = *result->feature_metadata().hdr_ratio;
    DVLOGFID(1, result->frame_number())
        << "Using HDR ratio=" << run_options.hdr_ratio;
  }

  // Disable HDRnet processing completely if the tonemap mode is set to contrast
  // curve, gamma value, or preset curve.
  if (buf_info.skip_hdrnet_processing) {
    run_options.hdrnet_enable = false;
    DVLOGFID(1, result->frame_number()) << "Disable HDRnet processing";
  }

  return run_options;
}

void HdrNetStreamManipulator::OnBuffersRendered(
    Camera3CaptureDescriptor& result,
    HdrNetStreamContext* stream_context,
    HdrNetRequestBufferInfo* request_buffer_info) {
  DCHECK(stream_context);
  DCHECK(request_buffer_info);
  switch (stream_context->mode) {
    case HdrNetStreamContext::Mode::kReplaceYuv:
      // Assign the release fence to all client-requested buffers the
      // HDRnet pipeline writes to. The FD ownership will be passed to
      // the client.
      for (auto& requested_buffer :
           request_buffer_info->client_requested_yuv_buffers) {
        if (!HaveSameAspectRatio(stream_context->hdrnet_stream.get(),
                                 requested_buffer.stream)) {
          continue;
        }
        requested_buffer.release_fence =
            DupWithCloExec(request_buffer_info->release_fence.get()).release();
        result.AppendOutputBuffer(
            Camera3StreamBuffer::MakeResultOutput(requested_buffer));
      }
      request_buffer_info->client_requested_yuv_buffers.clear();
      break;

    case HdrNetStreamContext::Mode::kAppendWithBlob:
      // The JPEG result buffer will be produced by
      // |still_capture_processor_| asynchronously.
      still_capture_processor_->QueuePendingYuvImage(
          result.frame_number(), *stream_context->still_capture_intermediate,
          std::move(request_buffer_info->release_fence));
      request_buffer_info->blob_intermediate_yuv_pending = false;
      break;
  }
}

bool HdrNetStreamManipulator::SetUpPipelineOnGpuThread() {
  DCHECK(hdrnet_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  TRACE_HDRNET();

  std::vector<Size> all_output_sizes;
  for (const auto& context : hdrnet_stream_context_) {
    all_output_sizes.emplace_back(context->hdrnet_stream->width,
                                  context->hdrnet_stream->height);
  }

  CachedPipelineResources* cache =
      hdrnet_gpu_resources_->GetCache<CachedPipelineResources>(
          CachedPipelineResources::kCachedPipelineResourcesId);
  if (!cache) {
    hdrnet_gpu_resources_->SetCache(
        CachedPipelineResources::kCachedPipelineResourcesId,
        std::make_unique<CachedPipelineResources>());
    cache = hdrnet_gpu_resources_->GetCache<CachedPipelineResources>(
        CachedPipelineResources::kCachedPipelineResourcesId);
  }
  CHECK(cache);

  const camera_metadata_t* locked_static_info = static_info_.getAndLock();
  for (const auto& context : hdrnet_stream_context_) {
    camera3_stream_t* stream = context->hdrnet_stream.get();
    TRACE_HDRNET_EVENT("HdrNetStreamManipulator::SetUpContextResources",
                       "width", stream->width, "height", stream->height);
    Size stream_size(stream->width, stream->height);
    std::vector<Size> viable_output_sizes;
    for (const auto& s : all_output_sizes) {
      if (s.width <= stream_size.width && s.height <= stream_size.height) {
        viable_output_sizes.push_back(s);
      }
    }

    {
      TRACE_HDRNET_EVENT("HdrNetStreamManipulator::CreateHdrnetProcessor");
      context->processor = cache->GetProcessor(stream_size);
      if (!context->processor) {
        cache->PutProcessor(
            stream_size,
            hdrnet_processor_factory_.Run(
                locked_static_info, hdrnet_gpu_resources_->gpu_task_runner()));
        context->processor = cache->GetProcessor(stream_size);
        if (!context->processor) {
          LOGF(ERROR) << "Failed to initialize HDRnet processor";
          ++hdrnet_metrics_.errors[HdrnetError::kInitializationError];
          return false;
        }
        context->processor->Initialize(hdrnet_gpu_resources_, stream_size,
                                       viable_output_sizes);
      }
    }

    {
      TRACE_HDRNET_EVENT("HdrNetStreamManipulator::CreateDenoiser");
      context->denoiser = cache->GetDenoiser(stream_size);
      if (!context->denoiser) {
        cache->PutDenoiser(
            stream_size,
            SpatiotemporalDenoiser::CreateInstance(
                {.frame_width = static_cast<int>(stream_size.width),
                 .frame_height = static_cast<int>(stream_size.height),
                 .mode = SpatiotemporalDenoiser::Mode::kIirMode}));
        context->denoiser = cache->GetDenoiser(stream_size);
        if (!context->denoiser) {
          LOGF(ERROR) << "Failed to initialize Spatiotemporal denoiser";
          ++hdrnet_metrics_.errors[HdrnetError::kInitializationError];
          return false;
        }
      }
    }

    TRACE_HDRNET_BEGIN("HdrNetStreamManipulator::AllocateIntermediateBuffers");

    constexpr uint32_t kBufferUsage =
        GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_TEXTURE;
    // Allocate the hdrnet buffers.
    constexpr int kNumExtraBuffer = kMaxDenoiserBurstLength + 5;
    for (int i = 0; i < stream->max_buffers + kNumExtraBuffer; ++i) {
      ScopedBufferHandle buffer = CameraBufferManager::AllocateScopedBuffer(
          stream->width, stream->height, stream->format, kBufferUsage);
      if (!buffer) {
        LOGF(ERROR) << "Cannot allocate HDRnet buffers";
        ++hdrnet_metrics_.errors[HdrnetError::kInitializationError];
        return false;
      }
      SharedImage shared_image = SharedImage::CreateFromBuffer(
          *buffer, Texture2D::Target::kTarget2D, true);
      if (!shared_image.y_texture().IsValid() ||
          !shared_image.uv_texture().IsValid()) {
        LOGF(ERROR) << "Cannot create SharedImage for the HDRnet buffer";
        ++hdrnet_metrics_.errors[HdrnetError::kInitializationError];
        return false;
      }
      // Let the SharedImage own the buffer.
      shared_image.SetDestructionCallback(
          base::BindOnce([](ScopedBufferHandle buffer) {}, std::move(buffer)));
      context->shared_images.emplace_back(std::move(shared_image));
      context->PushBuffer(i, base::ScopedFD());
    }

    if (context->original_stream->format == HAL_PIXEL_FORMAT_BLOB) {
      LOGF(INFO) << "Allocate still capture intermediate";
      context->still_capture_intermediate =
          CameraBufferManager::AllocateScopedBuffer(
              stream->width, stream->height, HAL_PIXEL_FORMAT_YCBCR_420_888,
              kBufferUsage);
    }

    {
      ScopedBufferHandle buffer = CameraBufferManager::AllocateScopedBuffer(
          stream->width, stream->height, stream->format, kBufferUsage);
      if (!buffer) {
        LOGF(ERROR) << "Cannot allocate denoiser intermediate buffer";
        return false;
      }
      SharedImage shared_image = SharedImage::CreateFromBuffer(
          *buffer, Texture2D::Target::kTarget2D, true);
      if (!shared_image.y_texture().IsValid() ||
          !shared_image.uv_texture().IsValid()) {
        LOGF(ERROR)
            << "Cannot create SharedImage for the denoiser intermediate buffer";
        return false;
      }
      // Let the SharedImage own the buffer.
      shared_image.SetDestructionCallback(
          base::BindOnce([](ScopedBufferHandle buffer) {}, std::move(buffer)));
      context->denoiser_intermediate = std::move(shared_image);
    }

    TRACE_HDRNET_END();
  }
  static_info_.unlock(locked_static_info);

  return true;
}

void HdrNetStreamManipulator::ResetStateOnGpuThread() {
  DCHECK(hdrnet_gpu_resources_->gpu_task_runner()->BelongsToCurrentThread());
  TRACE_HDRNET();

  still_capture_processor_->Reset();
  request_buffer_info_.clear();
  for (auto& ctx : hdrnet_stream_context_) {
    if (ctx->processor) {
      ctx->processor->TearDown();
    }
  }
  hdrnet_stream_context_.clear();
  request_stream_mapping_.clear();
  result_stream_mapping_.clear();

  UploadMetrics();
  hdrnet_metrics_ = HdrnetMetrics();
}

HdrNetStreamManipulator::HdrNetStreamContext*
HdrNetStreamManipulator::CreateHdrNetStreamContext(camera3_stream_t* requested,
                                                   uint32_t replace_format) {
  std::unique_ptr<HdrNetStreamContext> context =
      std::make_unique<HdrNetStreamContext>();
  context->original_stream = requested;
  context->hdrnet_stream = std::make_unique<camera3_stream_t>(*requested);
  context->hdrnet_stream->format = replace_format;
  if (requested->format == HAL_PIXEL_FORMAT_BLOB) {
    // We still need the BLOB stream for extracting the JPEG APPs segments, so
    // we add a new YUV stream instead of replacing the BLOB stream.
    context->mode = HdrNetStreamContext::Mode::kAppendWithBlob;

#if USE_IPU6 || USE_IPU6EP
    // On Intel platforms, the GRALLOC_USAGE_PRIVATE_1 usage bit tells the
    // camera HAL to process the stream using the still pipe for higher quality
    // output.
    context->hdrnet_stream->usage |= GRALLOC_USAGE_PRIVATE_1;
#endif  // USE_IPU6 || USE_IPU6EP
  }

  HdrNetStreamContext* addr = context.get();
  request_stream_mapping_[requested] = addr;
  result_stream_mapping_[context->hdrnet_stream.get()] = addr;
  hdrnet_stream_context_.emplace_back(std::move(context));
  return addr;
}

HdrNetStreamManipulator::HdrNetStreamContext*
HdrNetStreamManipulator::GetHdrNetContextFromRequestedStream(
    const camera3_stream_t* requested) {
  auto iter = request_stream_mapping_.find(requested);
  if (iter == request_stream_mapping_.end()) {
    return nullptr;
  }
  return iter->second;
}

HdrNetStreamManipulator::HdrNetStreamContext*
HdrNetStreamManipulator::GetHdrNetContextFromHdrNetStream(
    const camera3_stream_t* hdrnet) {
  auto iter = result_stream_mapping_.find(hdrnet);
  if (iter == result_stream_mapping_.end()) {
    return nullptr;
  }
  return iter->second;
}

void HdrNetStreamManipulator::OnOptionsUpdated(
    const base::Value::Dict& json_values) {
  ParseHdrnetJsonOptions(json_values, options_);

  bool denoiser_enable;
  if (LoadIfExist(json_values, kDenoiserEnable, &denoiser_enable)) {
    if (!options_.denoiser_enable && options_.denoiser_enable) {
      // Reset the denoiser temporal buffer whenever we switch on the denoiser
      // to avoid artifacts caused by stale data.
      for (auto& c : hdrnet_stream_context_) {
        c->should_reset_temporal_buffer = true;
      }
    }
    options_.denoiser_enable = denoiser_enable;
  }
  LoadIfExist(json_values, kDenoiserIirTemporalConvergence,
              &options_.iir_temporal_convergence);
  LoadIfExist(json_values, kDenoiserNumSpatialPasses,
              &options_.num_spatial_passes);
  LoadIfExist(json_values, kDenoiserSpatialStrength,
              &options_.spatial_strength);

  bool log_frame_metadata;
  if (LoadIfExist(json_values, kLogFrameMetadata, &log_frame_metadata)) {
    if (options_.log_frame_metadata && !log_frame_metadata) {
      // Dump frame metadata when metadata logging if turned off.
      metadata_logger_.DumpMetadata();
      metadata_logger_.Clear();
    }
    options_.log_frame_metadata = log_frame_metadata;
  }

  DVLOGF(1) << "HDRnet config:"
            << " hdrnet_enable=" << options_.hdrnet_enable
            << " dump_buffer=" << options_.dump_buffer
            << " log_frame_metadata=" << options_.log_frame_metadata
            << " hdr_ratio=" << options_.hdr_ratio
            << " max_gain_blend_threshold=" << options_.max_gain_blend_threshold
            << " spatial_filter_sigma=" << options_.spatial_filter_sigma
            << " range_filter_sigma=" << options_.range_filter_sigma
            << " iir_filter_strength=" << options_.iir_filter_strength;
}

void HdrNetStreamManipulator::UploadMetrics() {
  if (hdrnet_metrics_.errors.empty() &&
      (hdrnet_metrics_.num_concurrent_hdrnet_streams == 0 ||
       hdrnet_metrics_.num_frames_processed == 0)) {
    // Avoid uploading metrics short-lived session that does not really do
    // anything. Short-lived session can happen when we first open a camera,
    // where the framework and the HAL may re-configure the streams more than
    // once.
    return;
  }
  camera_metrics_->SendHdrnetStreamConfiguration(hdrnet_metrics_.stream_config);
  camera_metrics_->SendHdrnetMaxStreamSize(HdrnetStreamType::kYuv,
                                           hdrnet_metrics_.max_yuv_stream_size);
  camera_metrics_->SendHdrnetMaxStreamSize(
      HdrnetStreamType::kBlob, hdrnet_metrics_.max_blob_stream_size);
  camera_metrics_->SendHdrnetNumConcurrentStreams(
      hdrnet_metrics_.num_concurrent_hdrnet_streams);
  camera_metrics_->SendHdrnetMaxOutputBuffersRendered(
      hdrnet_metrics_.max_output_buffers_rendered);
  camera_metrics_->SendHdrnetNumStillShotsTaken(
      hdrnet_metrics_.num_still_shot_taken);

  if (hdrnet_metrics_.errors.empty()) {
    camera_metrics_->SendHdrnetError(HdrnetError::kNoError);
  } else {
    for (auto [e, c] : hdrnet_metrics_.errors) {
      if (e == HdrnetError::kNoError) {
        NOTREACHED();
        continue;
      }
      if (c > 0) {
        // Since we want to normalize all our metrics by camera sessions, we
        // only report whether an type of error is happened and print the number
        // of error occurrences as error.
        LOGF(ERROR) << "There were " << c << " occurrences of error "
                    << static_cast<int>(e);
        camera_metrics_->SendHdrnetError(e);
      }
    }
  }

  if (hdrnet_metrics_.num_frames_processed > 0) {
    camera_metrics_->SendHdrnetAvgLatency(
        HdrnetProcessingType::kPreprocessing,
        hdrnet_metrics_.accumulated_preprocessing_latency_us /
            hdrnet_metrics_.num_frames_processed);
    camera_metrics_->SendHdrnetAvgLatency(
        HdrnetProcessingType::kRgbPipeline,
        hdrnet_metrics_.accumulated_rgb_pipeline_latency_us /
            hdrnet_metrics_.num_frames_processed);
    camera_metrics_->SendHdrnetAvgLatency(
        HdrnetProcessingType::kPostprocessing,
        hdrnet_metrics_.accumulated_postprocessing_latency_us /
            hdrnet_metrics_.num_frames_processed);
  }
}

}  // namespace cros
