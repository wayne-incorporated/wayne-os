/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/effects/effects_stream_manipulator.h"

#include <GLES3/gl3.h>

#include <cutils/native_handle.h>
#include <hardware/camera3.h>
#include <sync/sync.h>

#include <unistd.h>
#include <algorithm>
#include <deque>
#include <numeric>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <base/containers/flat_set.h>
#include <base/containers/stack_container.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/functional/bind.h>
#include <base/functional/callback_forward.h>
#include <base/functional/callback_helpers.h>
#include <base/location.h>
#include <base/no_destructor.h>
#include <base/strings/string_util.h>
#include <base/threading/thread_checker.h>
#include <base/time/time.h>
#include <base/timer/timer.h>
#include <base/values.h>

#undef Status
#include <absl/status/status.h>

#include "camera/features/effects/tracing.h"
#include "camera/mojo/effects/effects_pipeline.mojom.h"
#include "common/camera_buffer_pool.h"
#include "common/camera_hal3_helpers.h"
#include "common/reloadable_config_file.h"
#include "common/still_capture_processor.h"
#include "common/stream_manipulator.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/camera_metrics.h"
#include "features/effects/effects_metrics.h"
#include "gpu/egl/egl_fence.h"
#include "gpu/gles/texture_2d.h"
#include "gpu/image_processor.h"
#include "gpu/shared_image.h"
#include "ml_core/effects_pipeline.h"
#include "ml_core/opencl_caching/constants.h"
#include "ml_core/opencl_caching/utils.h"

namespace cros {

namespace {

const int kSyncWaitTimeoutMs = 1000;
const base::TimeDelta kMaximumMetricsSessionDuration = base::Seconds(3600);

constexpr char kEffectKey[] = "effect";
constexpr char kBlurLevelKey[] = "blur_level";
constexpr char kGpuApiKey[] = "gpu_api";
constexpr char kRelightingGpuApiKey[] = "relighting_gpu_api";
constexpr char kBlurEnabled[] = "blur_enabled";
constexpr char kReplaceEnabled[] = "replace_enabled";
constexpr char kRelightEnabled[] = "relight_enabled";
constexpr char kSegmentationModelTypeKey[] = "segmentation_model_type";

constexpr uint32_t kRGBAFormat = HAL_PIXEL_FORMAT_RGBX_8888;
constexpr uint32_t kBufferUsage = GRALLOC_USAGE_HW_TEXTURE;

const base::FilePath kEffectsRunningMarker("/run/camera/effects_running");
const base::TimeDelta kEffectsRunningMarkerLifetime = base::Seconds(10);
// TODO(b:242631540) Find permanent location for this file
const base::FilePath kOverrideEffectsConfigFile(
    "/run/camera/effects/effects_config_override.json");

bool GetStringFromKey(const base::Value::Dict& obj,
                      const std::string& key,
                      std::string* value) {
  const std::string* val = obj.FindString(key);
  if (!val || val->empty()) {
    return false;
  }

  *value = *val;
  return true;
}

void LogAverageLatency(base::TimeDelta latency) {
  static base::NoDestructor<std::deque<float>> latencies;
  auto const count = static_cast<float>(latencies->size());
  if (count > 60) {
    auto avg = std::reduce(latencies->begin(), latencies->end()) / count;
    VLOGF(1) << "Avg frame latency: " << avg;
    latencies->clear();
  }
  latencies->push_back(latency.InMillisecondsF());
}

void DeleteEffectsMarkerFile() {
  if (!base::PathExists(kEffectsRunningMarker))
    return;

  if (!base::DeleteFile(kEffectsRunningMarker)) {
    LOGF(WARNING) << "Couldn't delete effects marker file";
  }
}

// Creates a file that indicates an attempt to start
// the effects pipeline has been made. If this causes the
// camera stack to crash, the file will be left there
// and the opencl-cacher-failsafe upstart job will
// clear the cache. Returns a timer object that will delete
// the marker file after the duration defined in kEffectsRunningMarkerLifetime
std::unique_ptr<base::OneShotTimer> CreateEffectsMarkerFile() {
  if (!base::WriteFile(kEffectsRunningMarker, "")) {
    LOGF(WARNING) << "Couldn't create effects marker file";
    return nullptr;
  }
  auto timer = std::make_unique<base::OneShotTimer>();
  timer->Start(FROM_HERE, kEffectsRunningMarkerLifetime,
               base::BindOnce(&DeleteEffectsMarkerFile));
  return timer;
}

class RenderedImageObserver : public ProcessedFrameObserver {
 public:
  explicit RenderedImageObserver(
      base::RepeatingCallback<void(int64_t, GLuint, uint32_t, uint32_t)>
          processed_frame_callback)
      : frame_processed_callback_(processed_frame_callback) {}
  void OnFrameProcessed(int64_t timestamp,
                        GLuint frame_texture,
                        uint32_t frame_width,
                        uint32_t frame_height) override {
    frame_processed_callback_.Run(timestamp, frame_texture, frame_width,
                                  frame_height);
  }

 private:
  base::RepeatingCallback<void(int64_t, GLuint, uint32_t, uint32_t)>
      frame_processed_callback_;
};

EffectsConfig ConvertMojoConfig(cros::mojom::EffectsConfigPtr effects_config) {
  // Note: We don't copy over the GPU api fields here, since we have no
  //       need to control them from Chrome at this stage. It will use
  //       the default from effects_pipeline_types.h
  auto config = EffectsConfig{
      .relight_enabled = effects_config->relight_enabled,
      .blur_enabled = effects_config->blur_enabled,
      .replace_enabled = effects_config->replace_enabled,
      .blur_level = static_cast<cros::BlurLevel>(effects_config->blur_level),
      .graph_max_frames_in_flight = effects_config->graph_max_frames_in_flight,
      .segmentation_model_type = static_cast<cros::SegmentationModelType>(
          effects_config->segmentation_model),
  };
  if (effects_config->background_filepath) {
    base::FilePath path =
        base::FilePath("/run/camera/")
            .Append(effects_config->background_filepath->path);
    base::strlcpy(config.background_image_asset, path.value().c_str(),
                  sizeof(config.background_image_asset));
  }
  if (effects_config->light_intensity) {
    config.light_intensity = *effects_config->light_intensity;
  }
  return config;
}

}  // namespace

class EffectsStreamManipulatorImpl : public EffectsStreamManipulator {
 public:
  // callback used to signal that an effect has taken effect.
  // Once the callback is fired it is guaranteed that all subsequent
  // frames will have the effect applied.
  // TODO(b:263440749): update callback type
  EffectsStreamManipulatorImpl(
      base::FilePath config_file_path,
      RuntimeOptions* runtime_options,
      std::unique_ptr<StillCaptureProcessor> still_capture_processor,
      void (*callback)(bool) = nullptr);
  ~EffectsStreamManipulatorImpl() override;

  // Implementations of StreamManipulator.
  bool Initialize(const camera_metadata_t* static_info,
                  StreamManipulator::Callbacks callbacks) override;
  bool ConfigureStreams(Camera3StreamConfiguration* stream_config,
                        const StreamEffectMap* stream_effects_map) override;
  bool OnConfiguredStreams(Camera3StreamConfiguration* stream_config) override;
  bool ConstructDefaultRequestSettings(
      android::CameraMetadata* default_request_settings, int type) override;
  bool ProcessCaptureRequest(Camera3CaptureDescriptor* request) override;
  bool ProcessCaptureResult(Camera3CaptureDescriptor result) override;
  void Notify(camera3_notify_msg_t msg) override;
  bool Flush() override;
  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner() override;
  void OnFrameProcessed(int64_t timestamp,
                        GLuint texture,
                        uint32_t width,
                        uint32_t height);

 private:
  struct StreamContext;

  // State related to a single frame capture.
  struct CaptureContext {
    // Checks if all work for this capture has finished, and if so, deallocates
    // `this`.
    void CheckForCompletion() &&;

    StreamContext* stream_context = nullptr;
    uint32_t frame_number = 0;
    std::optional<CameraBufferPool::Buffer> yuv_buffer;
    std::optional<CameraBufferPool::Buffer> yuv_buffer_copy;
    SharedImage yuv_image_copy;
    bool yuv_stream_appended = false;
    bool blob_result_pending = false;
    bool blob_intermediate_yuv_pending = false;
    bool still_capture_processor_pending = false;
  };

  // Per-stream state, spanning multiple frames.
  struct StreamContext {
    CaptureContext* GetCaptureContext(uint32_t frame_number);

    // The original stream requested by the client.
    camera3_stream_t* original_stream = nullptr;
    CameraEffectStreamType stream_type = CameraEffectStreamType::kYuv;

    // If this is a blob stream, this stream should be used as the input.
    camera3_stream_t* yuv_stream_for_blob = nullptr;

    // Will be set if the blob YUV stream above was created by us.
    std::unique_ptr<camera3_stream_t> yuv_stream_for_blob_owned;

    // Buffers for the YUV blob stream.
    std::unique_ptr<CameraBufferPool> yuv_buffer_pool;

    // Intermediate RGBA buffers for effects pipeline.
    std::unique_ptr<CameraBufferPool> rgba_buffer_pool;

    // In-flight still image capture requests for this stream.
    base::flat_map<uint32_t, CaptureContext> capture_contexts;

    // Time at which the most recent frame was processed for this stream.
    base::TimeTicks last_processed_frame_timestamp;
  };

  // States for async effects pipeline processing. On destroy, the output
  // buffers are returned to the client.
  struct ProcessContext {
    ProcessContext() = default;
    ProcessContext(const ProcessContext& other) = delete;
    ProcessContext& operator=(const ProcessContext& other) = delete;
    ProcessContext(ProcessContext&& other) = delete;
    ProcessContext& operator=(ProcessContext&& other) = delete;
    ~ProcessContext();

    CaptureResultCallback result_callback;
    uint32_t frame_number = 0;
    bool result_buffer_appended = false;
    Camera3StreamBuffer result_buffer;
    std::vector<Camera3StreamBuffer> copy_buffers;
    SharedImage yuv_image;
    std::optional<CameraBufferPool::Buffer> rgba_buffer;
    SharedImage rgba_image;
    base::TimeTicks processing_time_start;
  };

  struct PipelineResult {
    GLuint texture;
    int width;
    int height;
  };

  void OnOptionsUpdated(const base::Value::Dict& json_values);

  void SetEffect(EffectsConfig new_config);
  bool SetupGlThread(base::FilePath config_file_path);
  void ShutdownOnGlThread();
  void RenderEffect(std::unique_ptr<ProcessContext> process_context,
                    int64_t timestamp);
  void CreatePipeline(const base::FilePath& dlc_root_path);
  std::optional<int64_t> TryGetSensorTimestamp(Camera3CaptureDescriptor* desc);
  void UploadAndResetMetricsData();
  void ResetState();
  StreamContext* GetStreamContext(const camera3_stream_t*) const;
  void ReturnStillCaptureResult(Camera3CaptureDescriptor result);
  void OnFrameStarted(StreamContext& stream_context);
  void OnFrameCompleted(StreamContext& stream_context);
  void PostProcess(int64_t timestamp,
                   GLuint texture,
                   uint32_t width,
                   uint32_t height);
  bool ProcessStillCapture(uint32_t frame_number,
                           const Camera3StreamBuffer& result_buffer,
                           const SharedImage* result_image,
                           bool* result_buffer_appended);

  std::unique_ptr<ReloadableConfigFile> config_;
  base::FilePath config_file_path_;
  bool override_config_exists_ GUARDED_BY_CONTEXT(gl_thread_checker_) = false;
  RuntimeOptions* runtime_options_;
  StreamManipulator::Callbacks callbacks_;

  // Maximum number of frames that can be queued into effects pipeline.
  // Determined at stream configuration.
  uint32_t graph_max_frames_in_flight_ = 0;

  EffectsConfig active_runtime_effects_config_
      GUARDED_BY_CONTEXT(gl_thread_checker_) = EffectsConfig();
  // Config state. last_set_effect_ can be different to
  // active_runtime_effects_config_ when the effect is set
  // via the ReloadableConfig mechanism.
  EffectsConfig last_set_effect_config_ GUARDED_BY_CONTEXT(gl_thread_checker_) =
      EffectsConfig();

  std::unique_ptr<EffectsPipeline> pipeline_
      GUARDED_BY_CONTEXT(gl_thread_checker_);

  std::vector<std::unique_ptr<StreamContext>> stream_contexts_
      GUARDED_BY(stream_contexts_lock_);
  base::Lock stream_contexts_lock_;

  std::unique_ptr<EglContext> egl_context_
      GUARDED_BY_CONTEXT(gl_thread_checker_);
  std::unique_ptr<GpuImageProcessor> image_processor_
      GUARDED_BY_CONTEXT(gl_thread_checker_);

  int64_t last_timestamp_ GUARDED_BY_CONTEXT(gl_thread_checker_) = 0;
  std::unique_ptr<StillCaptureProcessor> still_capture_processor_
      GUARDED_BY_CONTEXT(gl_thread_checker_);

  base::flat_map<int64_t /*timestamp*/, std::unique_ptr<ProcessContext>>
      process_contexts_ GUARDED_BY_CONTEXT(gl_thread_checker_);

  CameraThread gl_thread_;

  void (*set_effect_callback_)(bool);

  THREAD_CHECKER(gl_thread_checker_);

  EffectsMetricsData metrics_;
  std::unique_ptr<EffectsMetricsUploader> metrics_uploader_;

  std::unique_ptr<base::OneShotTimer> marker_file_timer_;
};

EffectsStreamManipulatorImpl::ProcessContext::~ProcessContext() {
  if (result_callback.is_null()) {
    return;
  }

  if (VLOG_IS_ON(1)) {
    LogAverageLatency(base::TimeTicks::Now() - processing_time_start);
  }

  Camera3CaptureDescriptor result(
      camera3_capture_result_t{.frame_number = frame_number});
  if (!result_buffer_appended) {
    result.AppendOutputBuffer(std::move(result_buffer));
  }
  for (auto& copy_buffer : copy_buffers) {
    result.AppendOutputBuffer(std::move(copy_buffer));
  }
  result_callback.Run(std::move(result));
}

std::unique_ptr<EffectsStreamManipulator> EffectsStreamManipulator::Create(
    base::FilePath config_file_path,
    RuntimeOptions* runtime_options,
    std::unique_ptr<StillCaptureProcessor> still_capture_processor,
    void (*callback)(bool)) {
  return std::make_unique<EffectsStreamManipulatorImpl>(
      config_file_path, runtime_options, std::move(still_capture_processor),
      callback);
}

EffectsStreamManipulatorImpl::EffectsStreamManipulatorImpl(
    base::FilePath config_file_path,
    RuntimeOptions* runtime_options,
    std::unique_ptr<StillCaptureProcessor> still_capture_processor,
    void (*callback)(bool))
    : config_file_path_(config_file_path),
      runtime_options_(runtime_options),
      still_capture_processor_(std::move(still_capture_processor)),
      gl_thread_("EffectsGlThread"),
      set_effect_callback_(callback) {
  DETACH_FROM_THREAD(gl_thread_checker_);

  CHECK(gl_thread_.Start());

  // TODO(b/260656766): find a better task runner than the one from gl_thread
  // for metrics_uploader_. It would be nice to use
  // base::ThreadPool::CreateSequencedTaskRunner, but seems that
  // ThreadPoolInstance::Set() hasn't been set up in the camera stack, and it's
  // not the responsibility of this class to do that.
  metrics_uploader_ =
      std::make_unique<EffectsMetricsUploader>(gl_thread_.task_runner());

  bool ret;
  gl_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&EffectsStreamManipulatorImpl::SetupGlThread,
                     base::Unretained(this), std::move(config_file_path)),
      &ret);
  if (!ret) {
    LOGF(ERROR) << "Failed to start GL thread. Turning off feature by default";
    metrics_.RecordError(CameraEffectError::kGPUInitializationError);
  }
}

EffectsStreamManipulatorImpl::~EffectsStreamManipulatorImpl() {
  DeleteEffectsMarkerFile();
  // UploadAndResetMetricsData currently posts a task to the gl_thread task
  // runner (see constructor above). If we change that, we need to ensure the
  // upload task is complete before the destructor exits, or change the
  // behaviour to be synchronous in this situation.
  UploadAndResetMetricsData();
  gl_thread_.PostTaskSync(
      FROM_HERE,
      base::BindOnce(&EffectsStreamManipulatorImpl::ShutdownOnGlThread,
                     base::Unretained(this)));
  gl_thread_.Stop();
}

void EffectsStreamManipulatorImpl::ShutdownOnGlThread() {
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  TRACE_EFFECTS();
  config_.reset();
  marker_file_timer_.reset();
  if (pipeline_) {
    pipeline_.reset();
  }
  ResetState();
}

EffectsStreamManipulatorImpl::StreamContext*
EffectsStreamManipulatorImpl::GetStreamContext(
    const camera3_stream_t* stream) const {
  for (auto& s : stream_contexts_) {
    if (s->original_stream == stream || s->yuv_stream_for_blob == stream) {
      return s.get();
    }
  }
  return nullptr;
}

EffectsStreamManipulatorImpl::CaptureContext*
EffectsStreamManipulatorImpl::StreamContext::GetCaptureContext(
    uint32_t frame_number) {
  auto it = capture_contexts.find(frame_number);
  return it == capture_contexts.end() ? nullptr : &it->second;
}

void EffectsStreamManipulatorImpl::OnFrameStarted(
    StreamContext& stream_context) {
  auto now = base::TimeTicks::Now();
  auto stream_type = stream_context.yuv_stream_for_blob
                         ? CameraEffectStreamType::kBlob
                         : CameraEffectStreamType::kYuv;
  // If we've recorded at least one frame
  if (!stream_context.last_processed_frame_timestamp.is_null()) {
    metrics_.RecordFrameProcessingInterval(
        last_set_effect_config_, stream_type,
        now - stream_context.last_processed_frame_timestamp);
  }
  stream_context.last_processed_frame_timestamp = now;
}

void EffectsStreamManipulatorImpl::OnFrameCompleted(
    StreamContext& stream_context) {
  auto stream_type = stream_context.yuv_stream_for_blob
                         ? CameraEffectStreamType::kBlob
                         : CameraEffectStreamType::kYuv;
  metrics_.RecordFrameProcessingLatency(
      last_set_effect_config_, stream_type,
      base::TimeTicks::Now() - stream_context.last_processed_frame_timestamp);
}

void EffectsStreamManipulatorImpl::CaptureContext::CheckForCompletion() && {
  if (blob_result_pending || blob_intermediate_yuv_pending ||
      still_capture_processor_pending) {
    return;
  }
  TRACE_EFFECTS("frame_number", frame_number);
  stream_context->capture_contexts.erase(frame_number);
}

bool EffectsStreamManipulatorImpl::Initialize(
    const camera_metadata_t* static_info,
    StreamManipulator::Callbacks callbacks) {
  callbacks_ = std::move(callbacks);
  return true;
}

bool EffectsStreamManipulatorImpl::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effects) {
  TRACE_EFFECTS([&](perfetto::EventContext ctx) {
    stream_config->PopulateEventAnnotation(ctx);
  });
  UploadAndResetMetricsData();
  gl_thread_.PostTaskSync(
      FROM_HERE, base::BindOnce(&EffectsStreamManipulatorImpl::ResetState,
                                base::Unretained(this)));

  base::AutoLock lock(stream_contexts_lock_);
  base::span<camera3_stream_t* const> client_requested_streams =
      stream_config->GetStreams();
  std::vector<camera3_stream_t*> modified_streams;
  bool blob_stream_initialized = false;
  for (auto* s : client_requested_streams) {
    if (s->stream_type != CAMERA3_STREAM_OUTPUT) {
      // Only output buffers are supported.
      modified_streams.push_back(s);
      continue;
    }

    // Only one blob stream is supported.
    if (s->format == HAL_PIXEL_FORMAT_BLOB && blob_stream_initialized) {
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

      auto context = std::make_unique<StreamContext>();
      context->original_stream = s;
      modified_streams.push_back(s);

      // To support still image capture, we need to make sure the blob stream
      // has an associated YUV stream. If not, create a corresponding new YUV
      // stream. This YUV stream is fed to StillImageProcessor to be compressed
      // into jpeg blobs.
      if (s->format == HAL_PIXEL_FORMAT_BLOB) {
        context->stream_type = CameraEffectStreamType::kBlob;
        still_capture_processor_->Initialize(
            s, base::BindRepeating(
                   &EffectsStreamManipulatorImpl::ReturnStillCaptureResult,
                   base::Unretained(this)));
        blob_stream_initialized = true;

        // Find a matching YUV stream for this blob stream.
        for (auto* stream : stream_config->GetStreams()) {
          if (stream->stream_type == CAMERA3_STREAM_OUTPUT &&
              (stream->format == HAL_PIXEL_FORMAT_YCbCr_420_888 ||
               stream->format == HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED) &&
              stream->width == s->width && stream->height == s->height) {
            context->yuv_stream_for_blob = stream;
            break;
          }
        }

        // No matching YUV stream was found, so let's create a new one.
        if (!context->yuv_stream_for_blob) {
          context->yuv_stream_for_blob_owned =
              std::make_unique<camera3_stream_t>(camera3_stream_t{
                  .width = s->width,
                  .height = s->height,
                  .format = HAL_PIXEL_FORMAT_YCbCr_420_888,
                  .usage = GRALLOC_USAGE_SW_READ_OFTEN,
                  .crop_rotate_scale_degrees = s->crop_rotate_scale_degrees,
              });
          context->yuv_stream_for_blob =
              context->yuv_stream_for_blob_owned.get();
          modified_streams.push_back(context->yuv_stream_for_blob);
        }
      }
      metrics_.RecordStreamSize(context->stream_type, s->width * s->height);
      stream_contexts_.emplace_back(std::move(context));
    }
  }
  stream_config->SetStreams(modified_streams);
  TRACE_EVENT_INSTANT(kCameraTraceCategoryEffects, "ModifiedStreamConfig",
                      [&](perfetto::EventContext ctx) {
                        stream_config->PopulateEventAnnotation(ctx);
                      });
  return true;
}

void EffectsStreamManipulatorImpl::ResetState() {
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  process_contexts_.clear();
  still_capture_processor_->Reset();
  base::AutoLock lock(stream_contexts_lock_);
  for (auto& stream_context : stream_contexts_) {
    for (auto it = stream_context->capture_contexts.begin();
         it != stream_context->capture_contexts.end();) {
      auto& capture_context = it->second;
      ++it;
      std::move(capture_context).CheckForCompletion();
    }
  }
  stream_contexts_.clear();
}

bool EffectsStreamManipulatorImpl::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  TRACE_EFFECTS([&](perfetto::EventContext ctx) {
    stream_config->PopulateEventAnnotation(ctx);
  });
  base::span<camera3_stream_t* const> modified_streams =
      stream_config->GetStreams();
  std::vector<camera3_stream_t*> restored_streams;
  graph_max_frames_in_flight_ = 0;
  for (auto* modified_stream : modified_streams) {
    StreamContext* stream_context = GetStreamContext(modified_stream);
    if (!stream_context) {
      // Not a stream we care about, so just pass it through.
      restored_streams.push_back(modified_stream);
      continue;
    }

    // Allocate RGBA buffers for effects pipeline.
    if (modified_stream->format != HAL_PIXEL_FORMAT_BLOB) {
      const uint32_t max_num_buffers = modified_stream->max_buffers + 1;
      stream_context->rgba_buffer_pool =
          std::make_unique<CameraBufferPool>(CameraBufferPool::Options{
              .width = modified_stream->width,
              .height = modified_stream->height,
              .format = kRGBAFormat,
              .usage = kBufferUsage | GRALLOC_USAGE_SW_READ_NEVER,
              .max_num_buffers = max_num_buffers,
          });
      graph_max_frames_in_flight_ =
          std::max(graph_max_frames_in_flight_, max_num_buffers);
    }

    // Allocate a buffer pool for each blob stream in case we need to allocate
    // YUV buffers for those streams.
    if (auto* blob_stream = stream_context->yuv_stream_for_blob) {
      stream_context->yuv_buffer_pool =
          std::make_unique<CameraBufferPool>(CameraBufferPool::Options{
              .width = blob_stream->width,
              .height = blob_stream->height,
              .format = base::checked_cast<uint32_t>(blob_stream->format),
              .usage = blob_stream->usage,
              // Double the maximum number of buffers since we may make a copy
              // of each YUV buffer.
              .max_num_buffers = blob_stream->max_buffers * 2,
          });
      // If we created the YUV stream for this blob stream, don't forward it to
      // the client.
      if (!stream_context->yuv_stream_for_blob_owned) {
        restored_streams.push_back(modified_stream);
      }
      continue;
    }

    // This stream an effect output stream, so include it.
    restored_streams.push_back(modified_stream);
  }

  stream_config->SetStreams(restored_streams);
  TRACE_EVENT_INSTANT(kCameraTraceCategoryEffects, "ModifiedStreamConfig",
                      [&](perfetto::EventContext ctx) {
                        stream_config->PopulateEventAnnotation(ctx);
                      });
  return true;
}

bool EffectsStreamManipulatorImpl::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  return true;
}

bool EffectsStreamManipulatorImpl::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  TRACE_EFFECTS("frame_number", request->frame_number());
  if (request->has_input_buffer()) {
    // Skip reprocessing requests. We can't touch the output buffers of a
    // reprocessing request since they have to be produced from the given input
    // buffer.
    return true;
  }

  // Process still capture for each stream context.
  base::AutoLock lock(stream_contexts_lock_);
  for (auto& stream_context : stream_contexts_) {
    if (!stream_context->yuv_stream_for_blob) {
      continue;
    }
    // Find the matching output buffer for this blob stream.
    const Camera3StreamBuffer* output_buffer = nullptr;
    for (const auto& buffer : request->GetOutputBuffers()) {
      if (buffer.stream() == stream_context->original_stream) {
        output_buffer = &buffer;
        break;
      }
    }
    // If there's no output buffer, this stream isn't actively generating still
    // image captures and can be ignored.
    if (!output_buffer) {
      continue;
    }

    auto [ctx_it, was_inserted] = stream_context->capture_contexts.insert(
        std::make_pair(request->frame_number(),
                       CaptureContext{
                           .stream_context = stream_context.get(),
                           .frame_number = request->frame_number(),
                           .blob_result_pending = true,
                           .blob_intermediate_yuv_pending = true,
                           .still_capture_processor_pending = true,
                       }));
    DCHECK(was_inserted);
    CaptureContext& capture_context = ctx_it->second;

    still_capture_processor_->QueuePendingOutputBuffer(
        request->frame_number(), output_buffer->raw_buffer(), *request);

    // See if the YUV stream for this blob stream is present.
    bool has_yuv = false;
    for (const auto& buffer : request->GetOutputBuffers()) {
      if (buffer.stream() == stream_context->yuv_stream_for_blob) {
        has_yuv = true;
        break;
      }
    }

    // If not, append a new YUV buffer output.
    if (!has_yuv) {
      capture_context.yuv_buffer =
          stream_context->yuv_buffer_pool->RequestBuffer();
      if (!capture_context.yuv_buffer) {
        LOGF(ERROR) << "Failed to allocate buffer for frame "
                    << request->frame_number();
        metrics_.RecordError(CameraEffectError::kBufferAllocationError);
        return false;
      }
      request->AppendOutputBuffer(Camera3StreamBuffer::MakeRequestOutput({
          .stream = stream_context->yuv_stream_for_blob,
          .buffer = capture_context.yuv_buffer->handle(),
          .status = CAMERA3_BUFFER_STATUS_OK,
          .acquire_fence = -1,
          .release_fence = -1,
      }));
      capture_context.yuv_stream_appended = true;
    }
  }

  base::span<const int32_t> fps_range =
      request->GetMetadata<int32_t>(ANDROID_CONTROL_AE_TARGET_FPS_RANGE);
  if (!fps_range.empty()) {
    metrics_.RecordRequestedFrameRate(fps_range[1]);
  }
  return true;
}

std::optional<int64_t> EffectsStreamManipulatorImpl::TryGetSensorTimestamp(
    Camera3CaptureDescriptor* desc) {
  base::span<const int64_t> timestamp =
      desc->GetMetadata<int64_t>(ANDROID_SENSOR_TIMESTAMP);
  return timestamp.size() == 1 ? std::make_optional(timestamp[0] / 1000)
                               : std::nullopt;
}

bool EffectsStreamManipulatorImpl::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  TRACE_EFFECTS("frame_number", result.frame_number());

  auto processing_time_start = base::TimeTicks::Now();

  base::ScopedClosureRunner callback_action =
      StreamManipulator::MakeScopedCaptureResultCallbackRunner(
          callbacks_.result_callback, result);

  if (runtime_options_->sw_privacy_switch_state() ==
      mojom::CameraPrivacySwitchState::ON) {
    return true;
  }

  if (!pipeline_ && !runtime_options_->GetDlcRootPath().empty()) {
    CreatePipeline(base::FilePath(runtime_options_->GetDlcRootPath()));
  }
  if (!pipeline_)
    return true;

  auto new_config = ConvertMojoConfig(runtime_options_->GetEffectsConfig());
  if (active_runtime_effects_config_ != new_config) {
    active_runtime_effects_config_ = new_config;
    // Ignore the mojo config if the override config file is being used. This is
    // to avoid race conditions in tests where Chrome is also setting a default
    // (no-op) config mojo. Note that this flag isn't unset, so the camera
    // service must be restarted after the override config file has been
    // deleted.
    if (!override_config_exists_) {
      SetEffect(new_config);
    } else {
      LOGF(WARNING) << "Override config exists, ignoring mojo effect settings: "
                    << kOverrideEffectsConfigFile;
    }
  }

  auto timestamp = TryGetSensorTimestamp(&result);
  if (!timestamp.has_value()) {
    timestamp = last_timestamp_;
  }

  base::AutoLock lock(stream_contexts_lock_);
  size_t num_processed_streams = 0;
  base::flat_map<Size, std::unique_ptr<ProcessContext>> process_contexts;
  for (auto& result_buffer : result.AcquireOutputBuffers()) {
    StreamContext* stream_context = GetStreamContext(result_buffer.stream());
    if (!stream_context) {
      // Not a stream we care about, so just pass it through.
      result.AppendOutputBuffer(std::move(result_buffer));
      continue;
    }

    // If this a blob stream, extract its metadata.
    if (stream_context->yuv_stream_for_blob &&
        stream_context->original_stream == result_buffer.stream()) {
      CaptureContext& capture_context =
          *stream_context->GetCaptureContext(result.frame_number());
      still_capture_processor_->QueuePendingAppsSegments(
          result.frame_number(), *result_buffer.buffer(),
          base::ScopedFD(result_buffer.take_release_fence()));
      capture_context.blob_result_pending = false;
      std::move(capture_context).CheckForCompletion();
      continue;
    }

    // From this point onwards, we should only be dealing with YUV buffers.
    DCHECK_NE(result_buffer.stream()->format, HAL_PIXEL_FORMAT_BLOB);
    OnFrameStarted(*stream_context);

    if (result_buffer.status() != CAMERA3_BUFFER_STATUS_OK) {
      VLOGF(1) << "EffectsStreamManipulator received failed buffer: "
               << result.frame_number();
      metrics_.RecordError(CameraEffectError::kReceivedFailedBuffer);
      // Even though the buffer status is not OK, we still need to send a
      // response to the client to let them know their request was handled.
      result.AppendOutputBuffer(std::move(result_buffer));
      continue;
    }

    // Check existing output buffers for one with the same size so we can just
    // copy the results to this buffer instead of running the effects pipeline.
    const Size size(result_buffer.stream()->width,
                    result_buffer.stream()->height);
    auto existing_process_ctx_it = process_contexts.find(size);
    if (existing_process_ctx_it != process_contexts.end()) {
      existing_process_ctx_it->second->copy_buffers.push_back(
          std::move(result_buffer));
      continue;
    }

    bool yuv_stream_appended = false;
    if (!last_set_effect_config_.HasEnabledEffects() &&
        !ProcessStillCapture(result.frame_number(), result_buffer,
                             /*result_image=*/nullptr, &yuv_stream_appended)) {
      LOGF(ERROR) << "Failed to process YUV for still capture on frame "
                  << result.frame_number();
      // TODO(kamesan): Fail the blob capture queued to the still capture
      // processor.
    }

    auto [it, inserted] =
        process_contexts.emplace(size, std::make_unique<ProcessContext>());
    it->second->result_callback = callbacks_.result_callback,
    it->second->frame_number = result.frame_number(),
    it->second->result_buffer_appended = yuv_stream_appended,
    it->second->result_buffer = std::move(result_buffer),
    it->second->processing_time_start = processing_time_start,
    ++num_processed_streams;
  }

  if (last_set_effect_config_.HasEnabledEffects()) {
    for (auto& [size, process_context] : process_contexts) {
      RenderEffect(std::move(process_context), *timestamp);
    }
  }

  metrics_.RecordNumConcurrentStreams(stream_contexts_.size());
  metrics_.RecordNumConcurrentProcessedStreams(num_processed_streams);
  if (metrics_uploader_->TimeSinceLastUpload() >
      kMaximumMetricsSessionDuration) {
    UploadAndResetMetricsData();
  }

  return true;
}

void EffectsStreamManipulatorImpl::RenderEffect(
    std::unique_ptr<ProcessContext> process_context, int64_t timestamp) {
  TRACE_EFFECTS(
      perfetto::Flow::ProcessScoped(process_context->result_buffer.flow_id()),
      "frame_number", process_context->frame_number, "timestamp", timestamp);
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  DCHECK_EQ(process_context->result_buffer.status(), CAMERA3_BUFFER_STATUS_OK);

  stream_contexts_lock_.AssertAcquired();
  StreamContext* stream_context =
      GetStreamContext(process_context->result_buffer.stream());
  DCHECK_NE(stream_context, nullptr);

  if (!process_context->result_buffer.WaitOnAndClearReleaseFence(
          kSyncWaitTimeoutMs)) {
    LOGF(ERROR) << "Timed out waiting for input buffer";
    metrics_.RecordError(CameraEffectError::kSyncWaitTimeout);
    return;
  }

  process_context->yuv_image = SharedImage::CreateFromBuffer(
      *process_context->result_buffer.buffer(), Texture2D::Target::kTarget2D,
      /*separate_yuv_textures=*/true);
  if (!process_context->yuv_image.IsValid()) {
    LOGF(ERROR) << "Failed to create YUV shared image";
    metrics_.RecordError(CameraEffectError::kGPUImageInitializationFailed);
    return;
  }
  DCHECK_NE(stream_context->rgba_buffer_pool, nullptr);
  process_context->rgba_buffer =
      stream_context->rgba_buffer_pool->RequestBuffer();
  if (!process_context->rgba_buffer) {
    LOGF(ERROR) << "Failed to allocate RGBA buffer";
    metrics_.RecordError(CameraEffectError::kBufferAllocationError);
    return;
  }
  process_context->rgba_image = SharedImage::CreateFromBuffer(
      *process_context->rgba_buffer->handle(), Texture2D::Target::kTarget2D,
      /*separate_yuv_textures=*/false);
  if (!process_context->rgba_image.IsValid()) {
    LOGF(ERROR) << "Failed to create RGBA shared image";
    metrics_.RecordError(CameraEffectError::kGPUImageInitializationFailed);
    return;
  }
  DCHECK_EQ(process_context->yuv_image.y_texture().width(),
            process_context->rgba_image.texture().width());
  DCHECK_EQ(process_context->yuv_image.y_texture().height(),
            process_context->rgba_image.texture().height());
  if (!image_processor_->NV12ToRGBA(process_context->yuv_image.y_texture(),
                                    process_context->yuv_image.uv_texture(),
                                    process_context->rgba_image.texture())) {
    LOGF(ERROR) << "Failed to convert from YUV to RGB";
    metrics_.RecordError(CameraEffectError::kYUVConversionFailed);
    return;
  }
  glFinish();

  // Mediapipe requires timestamps to be strictly increasing for a given
  // pipeline. If we receive non-monotonic timestamps or render the pipeline
  // for multiple streams in parallel, make sure the same timestamp isn't
  // repeated.
  timestamp = std::max(timestamp, last_timestamp_ + 1);
  last_timestamp_ = timestamp;

  auto [it, inserted] = process_contexts_.emplace(
      std::make_pair(timestamp, std::move(process_context)));
  DCHECK(inserted);

  if (!pipeline_->ProcessFrame(timestamp,
                               it->second->rgba_image.texture().handle(),
                               it->second->rgba_image.texture().width(),
                               it->second->rgba_image.texture().height())) {
    LOGF(ERROR) << "Failed to process effects pipeline";
    metrics_.RecordError(CameraEffectError::kPipelineFailed);
    process_contexts_.erase(it);
  }
}

void EffectsStreamManipulatorImpl::Notify(camera3_notify_msg_t msg) {
  callbacks_.notify_callback.Run(std::move(msg));
}

bool EffectsStreamManipulatorImpl::Flush() {
  return true;
}

scoped_refptr<base::SingleThreadTaskRunner>
EffectsStreamManipulatorImpl::GetTaskRunner() {
  return gl_thread_.task_runner();
}

void EffectsStreamManipulatorImpl::OnFrameProcessed(int64_t timestamp,
                                                    GLuint texture,
                                                    uint32_t width,
                                                    uint32_t height) {
  TRACE_EFFECTS("timestamp", timestamp);

  // Synchronously wait until the texture is consumed before the pipeline
  // recycles it.
  glFinish();

  gl_thread_.PostTaskSync(
      FROM_HERE, base::BindOnce(&EffectsStreamManipulatorImpl::PostProcess,
                                base::Unretained(this), timestamp, texture,
                                width, height));
}

void EffectsStreamManipulatorImpl::PostProcess(int64_t timestamp,
                                               GLuint texture,
                                               uint32_t width,
                                               uint32_t height) {
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  TRACE_EFFECTS("timestamp", timestamp);

  if (process_contexts_.count(timestamp) == 0) {
    LOGF(WARNING) << "Drop pipeline result at " << timestamp
                  << " since context is gone";
    return;
  }
  std::unique_ptr<ProcessContext> process_context =
      std::move(process_contexts_.at(timestamp));
  process_contexts_.erase(timestamp);
  camera3_stream_buffer_t& result_buffer =
      process_context->result_buffer.mutable_raw_buffer();

  // The pipeline produces a GL texture, which needs to be synchronously
  // converted to YUV on this thread (because that's where the GL context
  // is bound). However, the pipeline must be prevented from recycling the
  // texture while the color space conversion is in progress. To facilitate
  // this, we:
  //
  // 1. Synchronously convert RGB to YUV.
  // 2. Unblock OnFrameProcessed to return the texture to the pipeline.
  //
  DCHECK_EQ(width, process_context->yuv_image.y_texture().width());
  DCHECK_EQ(height, process_context->yuv_image.y_texture().height());
  Texture2D texture_2d(texture, kRGBAFormat, width, height);
  if (image_processor_->RGBAToNV12(texture_2d,
                                   process_context->yuv_image.y_texture(),
                                   process_context->yuv_image.uv_texture())) {
    glFinish();
  } else {
    LOGF(ERROR) << "Failed to convert from RGB to YUV";
    metrics_.RecordError(CameraEffectError::kYUVConversionFailed);
    result_buffer.status = CAMERA3_BUFFER_STATUS_ERROR;
  }
  texture_2d.Release();
  texture = 0;

  if (result_buffer.status != CAMERA3_BUFFER_STATUS_OK) {
    return;
  }

  for (auto& copy_buffer : process_context->copy_buffers) {
    camera3_stream_buffer_t& raw_copy_buffer = copy_buffer.mutable_raw_buffer();
    if (!copy_buffer.WaitOnAndClearReleaseFence(kSyncWaitTimeoutMs)) {
      metrics_.RecordError(CameraEffectError::kSyncWaitTimeout);
      raw_copy_buffer.status = CAMERA3_BUFFER_STATUS_ERROR;
      continue;
    }
    auto copy_image = SharedImage::CreateFromBuffer(
        *copy_buffer.buffer(), Texture2D::Target::kTarget2D,
        /*separate_yuv_textures=*/true);
    if (!copy_image.IsValid()) {
      metrics_.RecordError(CameraEffectError::kGPUImageInitializationFailed);
      raw_copy_buffer.status = CAMERA3_BUFFER_STATUS_ERROR;
      continue;
    }
    if (!image_processor_->YUVToYUV(process_context->yuv_image.y_texture(),
                                    process_context->yuv_image.uv_texture(),
                                    copy_image.y_texture(),
                                    copy_image.uv_texture())) {
      metrics_.RecordError(CameraEffectError::kYUVConversionFailed);
      raw_copy_buffer.status = CAMERA3_BUFFER_STATUS_ERROR;
      continue;
    }
    raw_copy_buffer.release_fence = EglFence().GetNativeFd().release();
    raw_copy_buffer.status = CAMERA3_BUFFER_STATUS_OK;
  }

  base::AutoLock lock(stream_contexts_lock_);

  if (!ProcessStillCapture(process_context->frame_number,
                           process_context->result_buffer,
                           &process_context->yuv_image,
                           &process_context->result_buffer_appended)) {
    LOGF(ERROR) << "Failed to process YUV for still capture on frame "
                << process_context->frame_number;
    // TODO(kamesan): Fail the blob capture queued to the still capture
    // processor.
  }

  if (StreamContext* stream_context = GetStreamContext(result_buffer.stream)) {
    OnFrameCompleted(*stream_context);
  }
}

void EffectsStreamManipulatorImpl::ReturnStillCaptureResult(
    Camera3CaptureDescriptor result) {
  TRACE_EFFECTS();
  {
    base::AutoLock lock(stream_contexts_lock_);
    for (const auto& buffer : result.GetOutputBuffers()) {
      StreamContext* stream_context = GetStreamContext(buffer.stream());
      if (!stream_context)
        continue;
      CaptureContext& capture_context =
          *stream_context->GetCaptureContext(result.frame_number());
      capture_context.yuv_buffer = {};
      capture_context.still_capture_processor_pending = false;
      OnFrameCompleted(*stream_context);
      std::move(capture_context).CheckForCompletion();
    }
    metrics_.RecordStillShotTaken();
  }
  callbacks_.result_callback.Run(std::move(result));
}

void EffectsStreamManipulatorImpl::OnOptionsUpdated(
    const base::Value::Dict& json_values) {
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  LOGF(INFO) << "Reloadable Options update detected";
  CHECK(pipeline_);

  override_config_exists_ = base::PathExists(kOverrideEffectsConfigFile);

  EffectsConfig new_config;
  std::string effect;
  if (GetStringFromKey(json_values, kEffectKey, &effect)) {
    if (effect == std::string("blur")) {
      new_config.blur_enabled = true;
    } else if (effect == std::string("replace")) {
      new_config.replace_enabled = true;
    } else if (effect == std::string("relight")) {
      new_config.relight_enabled = true;
    } else if (effect == std::string("blur_relight")) {
      new_config.blur_enabled = true;
      new_config.relight_enabled = true;
    } else if (effect == std::string("none")) {
      new_config.blur_enabled = false;
      new_config.relight_enabled = false;
      new_config.replace_enabled = false;
    } else {
      LOGF(WARNING) << "Unknown Effect: " << effect;
      return;
    }
    LOGF(INFO) << "Effect Updated: " << effect;
  }
  LoadIfExist(json_values, kBlurEnabled, &new_config.blur_enabled);
  LoadIfExist(json_values, kReplaceEnabled, &new_config.replace_enabled);
  LoadIfExist(json_values, kRelightEnabled, &new_config.relight_enabled);

  std::string blur_level;
  if (GetStringFromKey(json_values, kBlurLevelKey, &blur_level)) {
    if (blur_level == "lowest") {
      new_config.blur_level = BlurLevel::kLowest;
    } else if (blur_level == "light") {
      new_config.blur_level = BlurLevel::kLight;
    } else if (blur_level == "medium") {
      new_config.blur_level = BlurLevel::kMedium;
    } else if (blur_level == "heavy") {
      new_config.blur_level = BlurLevel::kHeavy;
    } else if (blur_level == "maximum") {
      new_config.blur_level = BlurLevel::kMaximum;
    } else {
      LOGF(WARNING) << "Unknown Blur Level: " << blur_level;
      return;
    }
    LOGF(INFO) << "Blur Level: " << blur_level;
  }

  std::string gpu_api;
  if (GetStringFromKey(json_values, kGpuApiKey, &gpu_api)) {
    if (gpu_api == "opengl") {
      new_config.segmentation_gpu_api = GpuApi::kOpenGL;
      new_config.relighting_gpu_api = GpuApi::kOpenGL;
    } else if (gpu_api == "opencl") {
      new_config.segmentation_gpu_api = GpuApi::kOpenCL;
      new_config.relighting_gpu_api = GpuApi::kOpenCL;
    } else if (gpu_api == "vulkan") {
      new_config.segmentation_gpu_api = GpuApi::kVulkan;
      // Relighting stays as OpenCL in the Vulkan case
      new_config.relighting_gpu_api = GpuApi::kOpenCL;
    } else if (gpu_api == "any") {
      new_config.segmentation_gpu_api = GpuApi::kAny;
      new_config.relighting_gpu_api = GpuApi::kAny;
    } else {
      LOGF(WARNING) << "Unknown GPU API: " << gpu_api;
      return;
    }
    LOGF(INFO) << "GPU API: " << gpu_api;
  }

  std::string relighting_gpu_api;
  if (GetStringFromKey(json_values, kRelightingGpuApiKey,
                       &relighting_gpu_api)) {
    if (relighting_gpu_api == "opengl") {
      new_config.relighting_gpu_api = GpuApi::kOpenGL;
    } else if (relighting_gpu_api == "opencl") {
      new_config.relighting_gpu_api = GpuApi::kOpenCL;
    } else if (relighting_gpu_api == "any") {
      new_config.relighting_gpu_api = GpuApi::kAny;
    } else {
      LOGF(WARNING) << "Unknown Relighting GPU API: " << gpu_api;
      return;
    }
    LOGF(INFO) << "Relighting GPU API: " << relighting_gpu_api;
  }

  std::string segmentation_model_type;
  if (GetStringFromKey(json_values, kSegmentationModelTypeKey,
                       &segmentation_model_type)) {
    if (segmentation_model_type == "hd") {
      new_config.segmentation_model_type = SegmentationModelType::kHd;
    } else if (segmentation_model_type == "full") {
      new_config.segmentation_model_type = SegmentationModelType::kFull;
    } else {
      LOGF(WARNING) << "Unknown Segmentation Model Type: "
                    << segmentation_model_type;
      return;
    }
    LOGF(INFO) << "Segmentation Model Type: " << segmentation_model_type;
  }

  // Only apply the effect if something changed, as sometimes this function
  // can get called several times after one file save which is expensive.
  if (new_config != last_set_effect_config_) {
    SetEffect(std::move(new_config));
  }
}

void EffectsStreamManipulatorImpl::SetEffect(EffectsConfig new_config) {
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  CHECK(pipeline_);
  // The maximum number of in-flight frames is determined in this SM.
  CHECK_GT(graph_max_frames_in_flight_, 0);
  new_config.graph_max_frames_in_flight =
      base::checked_cast<int>(graph_max_frames_in_flight_);

  pipeline_->SetEffect(&new_config, set_effect_callback_);
  last_set_effect_config_ = new_config;

  if (new_config.HasEnabledEffects()) {
    metrics_.RecordSelectedEffect(new_config);
  }
}

bool EffectsStreamManipulatorImpl::SetupGlThread(
    base::FilePath config_file_path) {
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  TRACE_EFFECTS();

  if (!egl_context_) {
    egl_context_ = EglContext::GetSurfacelessContext();
    if (!egl_context_->IsValid()) {
      LOGF(ERROR) << "Failed to create EGL context";
      return false;
    }
  }
  if (!egl_context_->MakeCurrent()) {
    LOGF(ERROR) << "Failed to make EGL context current";
    return false;
  }

  image_processor_ = std::make_unique<GpuImageProcessor>();
  if (!image_processor_) {
    LOGF(ERROR) << "Failed to create GpuImageProcessor";
    return false;
  }

  return true;
}

void EffectsStreamManipulatorImpl::CreatePipeline(
    const base::FilePath& dlc_root_path) {
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  // Check to see if the cache dir is empty, and if so,
  // point the pipeline to the prebuilt cache as this may
  // indicate the opencl_cacher tool hasn't had the chance
  // to run or complete yet. Niche edge case, but it does
  // cause a large startup delay for the user. This is particularly
  // true when running behind a chrome flag, as the cacher
  // tool doesn't run on a UI restart.
  base::FilePath cache_dir_override("");
  // Don't override the cache if the marker file exists,
  // since we may be trying to recover from a bad cache.
  if (!base::PathExists(kEffectsRunningMarker)) {
    auto default_cache_dir = base::FilePath(kOpenCLCachingDir);
    if (DirIsEmpty(default_cache_dir)) {
      cache_dir_override = PrebuiltCacheDir(dlc_root_path);
      LOGF(INFO) << "OpenCL cache at " << default_cache_dir
                 << " is empty, using " << cache_dir_override << " instead.";
    }
  }

  marker_file_timer_ = CreateEffectsMarkerFile();

  pipeline_ = EffectsPipeline::Create(dlc_root_path, egl_context_->Get(),
                                      cache_dir_override);
  pipeline_->SetRenderedImageObserver(std::make_unique<RenderedImageObserver>(
      base::BindRepeating(&EffectsStreamManipulatorImpl::OnFrameProcessed,
                          base::Unretained(this))));

  config_ =
      std::make_unique<ReloadableConfigFile>(ReloadableConfigFile::Options{
          .default_config_file_path = config_file_path_,
          .override_config_file_path = kOverrideEffectsConfigFile,
      });
  if (!config_->IsValid()) {
    LOGF(WARNING) << "Cannot load valid JSON config";
  }
  config_->SetCallback(base::BindRepeating(
      &EffectsStreamManipulatorImpl::OnOptionsUpdated, base::Unretained(this)));
}

void EffectsStreamManipulatorImpl::UploadAndResetMetricsData() {
  EffectsMetricsData metrics_copy(metrics_);
  metrics_ = EffectsMetricsData();
  metrics_uploader_->UploadMetricsData(std::move(metrics_copy));
}

bool EffectsStreamManipulatorImpl::ProcessStillCapture(
    uint32_t frame_number,
    const Camera3StreamBuffer& result_buffer,
    const SharedImage* result_image,
    bool* result_buffer_appended) {
  stream_contexts_lock_.AssertAcquired();
  DCHECK_CALLED_ON_VALID_THREAD(gl_thread_checker_);
  TRACE_EFFECTS("frame_number", frame_number);

  StreamContext* stream_context = nullptr;
  for (auto& s : stream_contexts_) {
    if (s->yuv_stream_for_blob == result_buffer.stream()) {
      stream_context = s.get();
      break;
    }
  }
  if (!stream_context) {
    return true;
  }
  CaptureContext* capture_context =
      stream_context->GetCaptureContext(frame_number);
  if (!capture_context) {
    return true;
  }
  *result_buffer_appended = capture_context->yuv_stream_appended;

  DCHECK(capture_context->blob_intermediate_yuv_pending);
  capture_context->blob_intermediate_yuv_pending = false;

  buffer_handle_t queued_buffer = *result_buffer.buffer();
  base::ScopedFD release_fence;

  // If the still capture YUV is not appended, make a copy for processing
  // blob so we can return it at the same time.
  if (!capture_context->yuv_stream_appended) {
    // Create shared image on the result buffer if there's not one.
    SharedImage yuv_image;
    if (!result_image) {
      yuv_image = SharedImage::CreateFromBuffer(*result_buffer.buffer(),
                                                Texture2D::Target::kTarget2D,
                                                /*separate_yuv_textures=*/true);
      if (!yuv_image.IsValid()) {
        LOGF(ERROR) << "Failed to create YUV shared image for frame "
                    << frame_number;
        metrics_.RecordError(CameraEffectError::kGPUImageInitializationFailed);
        return false;
      }
      result_image = &yuv_image;
    }

    capture_context->yuv_buffer_copy =
        stream_context->yuv_buffer_pool->RequestBuffer();
    if (!capture_context->yuv_buffer_copy) {
      LOGF(ERROR) << "Failed to allocate YUV buffer for frame " << frame_number;
      metrics_.RecordError(CameraEffectError::kBufferAllocationError);
      return false;
    }
    capture_context->yuv_image_copy = SharedImage::CreateFromBuffer(
        *capture_context->yuv_buffer_copy->handle(),
        Texture2D::Target::kTarget2D,
        /*separate_yuv_textures=*/true);
    if (!capture_context->yuv_image_copy.IsValid()) {
      LOGF(ERROR) << "Failed to initialize GPU image for frame "
                  << frame_number;
      metrics_.RecordError(CameraEffectError::kGPUImageInitializationFailed);
      return false;
    }
    if (!image_processor_->YUVToYUV(
            result_image->y_texture(), result_image->uv_texture(),
            capture_context->yuv_image_copy.y_texture(),
            capture_context->yuv_image_copy.uv_texture())) {
      LOGF(ERROR) << "Failed to copy image with GPU for frame " << frame_number;
      metrics_.RecordError(CameraEffectError::kYUVConversionFailed);
      return false;
    }

    queued_buffer = *capture_context->yuv_buffer_copy->handle();
    release_fence = EglFence().GetNativeFd();
  }

  still_capture_processor_->QueuePendingYuvImage(frame_number, queued_buffer,
                                                 std::move(release_fence));
  return true;
}

}  // namespace cros
