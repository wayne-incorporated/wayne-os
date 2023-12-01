/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/stream_manipulator_manager.h"

#include <utility>

#include <base/files/file_path.h>
#include <base/synchronization/lock.h>
#include <base/thread_annotations.h>

#include "common/camera_buffer_handle.h"
#include "common/camera_hal3_helpers.h"
#include "common/common_tracing.h"
#include "common/still_capture_processor_impl.h"
#include "common/stream_manipulator.h"
#include "common/sw_privacy_switch_stream_manipulator.h"
#include "cros-camera/camera_mojo_channel_manager.h"
#include "cros-camera/camera_mojo_channel_manager_token.h"
#include "cros-camera/jpeg_compressor.h"
#include "cros-camera/tracing.h"
#include "features/feature_profile.h"
#include "features/rotate_and_crop/rotate_and_crop_stream_manipulator.h"
#include "features/zsl/zsl_stream_manipulator.h"
#include "gpu/gpu_resources.h"

#if USE_CAMERA_FEATURE_DIAGNOSTICS
#include "common/analyze_frame/frame_analysis_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_HDRNET
#include "features/gcam_ae/gcam_ae_stream_manipulator.h"
#include "features/hdrnet/hdrnet_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_AUTO_FRAMING
#include "features/auto_framing/auto_framing_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_EFFECTS
#include "features/effects/effects_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_FACE_DETECTION
#include "features/face_detection/face_detection_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_FRAME_ANNOTATOR
#include "features/frame_annotator/frame_annotator_loader_stream_manipulator.h"
#endif

#if USE_CAMERA_FEATURE_PORTRAIT_MODE
#include "features/portrait_mode/portrait_mode_stream_manipulator.h"
#endif

namespace cros {

namespace {

void MaybeEnableHdrNetStreamManipulator(
    const FeatureProfile& feature_profile,
    StreamManipulatorManager::CreateOptions& create_options,
    GpuResources* gpu_resources,
    std::vector<std::unique_ptr<StreamManipulator>>* out_stream_manipulators) {
#if USE_CAMERA_FEATURE_HDRNET
  if (!feature_profile.IsEnabled(FeatureProfile::FeatureType::kHdrnet)) {
    return;
  }
  constexpr const char kIntelIpu6CameraModuleName[] =
      "Intel IPU6 Camera HAL Module";
  if (create_options.camera_module_name == kIntelIpu6CameraModuleName) {
    // The pipeline looks like:
    //        ____       ________       _________
    //   --> |    | --> |        | --> |         | -->
    //       | FD |     | HDRnet |     | Gcam AE |
    //   <== |____| <== |________| <== |_________| <==
    //
    //   --> capture request flow
    //   ==> capture result flow
    //
    // Why the pipeline is organized this way:
    // * FaceDetection (if present) is placed before HDRnet because we want to
    //   run face detection on result frames rendered by HDRnet so we can
    //   better detect the underexposed faces.
    // * Gcam AE is placed after HDRnet because it needs raw result frames as
    //   input to get accurate AE metering, and because Gcam AE produces the
    //   HDR ratio needed by HDRnet to render the output frame.

#if USE_CAMERA_FEATURE_FACE_DETECTION
    if (feature_profile.IsEnabled(
            FeatureProfile::FeatureType::kFaceDetection)) {
      out_stream_manipulators->emplace_back(
          std::make_unique<FaceDetectionStreamManipulator>(
              feature_profile.GetConfigFilePath(
                  FeatureProfile::FeatureType::kFaceDetection),
              std::move(create_options.set_face_detection_result_callback)));
      LOGF(INFO) << "FaceDetectionStreamManipulator enabled";
    }
#endif

    std::unique_ptr<JpegCompressor> jpeg_compressor =
        JpegCompressor::GetInstance(CameraMojoChannelManager::GetInstance());
    out_stream_manipulators->emplace_back(
        std::make_unique<HdrNetStreamManipulator>(
            gpu_resources,
            feature_profile.GetConfigFilePath(
                FeatureProfile::FeatureType::kHdrnet),
            std::make_unique<StillCaptureProcessorImpl>(
                std::move(jpeg_compressor))));
    LOGF(INFO) << "HdrNetStreamManipulator enabled";
    if (feature_profile.IsEnabled(FeatureProfile::FeatureType::kGcamAe)) {
      out_stream_manipulators->emplace_back(
          std::make_unique<GcamAeStreamManipulator>(
              feature_profile.GetConfigFilePath(
                  FeatureProfile::FeatureType::kGcamAe)));
      LOGF(INFO) << "GcamAeStreamManipulator enabled";
    }
  }
#endif
}

void MaybeEnableAutoFramingStreamManipulator(
    const FeatureProfile& feature_profile,
    StreamManipulator::RuntimeOptions* runtime_options,
    GpuResources* gpu_resources,
    std::vector<std::unique_ptr<StreamManipulator>>* out_stream_manipulators) {
#if USE_CAMERA_FEATURE_AUTO_FRAMING
  if (feature_profile.IsEnabled(FeatureProfile::FeatureType::kAutoFraming)) {
    std::unique_ptr<JpegCompressor> jpeg_compressor =
        JpegCompressor::GetInstance(CameraMojoChannelManager::GetInstance());
    std::unique_ptr<StillCaptureProcessor> still_capture_processor =
        std::make_unique<StillCaptureProcessorImpl>(std::move(jpeg_compressor));
    out_stream_manipulators->emplace_back(
        std::make_unique<AutoFramingStreamManipulator>(
            runtime_options, gpu_resources,
            feature_profile.GetConfigFilePath(
                FeatureProfile::FeatureType::kAutoFraming),
            std::move(still_capture_processor)));
    LOGF(INFO) << "AutoFramingStreamManipulator enabled";
  }
#endif
}

}  // namespace

StreamManipulatorManager::StreamManipulatorManager(
    CreateOptions create_options,
    StreamManipulator::RuntimeOptions* runtime_options,
    GpuResources* gpu_resources,
    CameraMojoChannelManagerToken* mojo_manager_token)
    : default_capture_result_thread_("DefaultCaptureResultThread") {
  CHECK(default_capture_result_thread_.Start());
  TRACE_COMMON();

  FeatureProfile feature_profile;

#if USE_CAMERA_FEATURE_FRAME_ANNOTATOR
  stream_manipulators_.emplace_back(
      std::make_unique<FrameAnnotatorLoaderStreamManipulator>());
  LOGF(INFO) << "FrameAnnotatorLoaderStreamManipulator enabled";
#endif

#if USE_CAMERA_FEATURE_PORTRAIT_MODE
  stream_manipulators_.emplace_back(
      std::make_unique<PortraitModeStreamManipulator>(mojo_manager_token));
  LOGF(INFO) << "PortraitModeStreamManipulator enabled";
#endif

  stream_manipulators_.emplace_back(
      std::make_unique<RotateAndCropStreamManipulator>(
          std::make_unique<StillCaptureProcessorImpl>(
              JpegCompressor::GetInstance(
                  CameraMojoChannelManager::GetInstance()))));
  LOGF(INFO) << "RotateAndCropStreamManipulator enabled";

  MaybeEnableAutoFramingStreamManipulator(feature_profile, runtime_options,
                                          gpu_resources, &stream_manipulators_);

#if USE_CAMERA_FEATURE_EFFECTS
  LOGF(INFO) << "Service built with effects support";
  if (feature_profile.IsEnabled(FeatureProfile::FeatureType::kEffects)) {
    std::unique_ptr<JpegCompressor> jpeg_compressor =
        JpegCompressor::GetInstance(CameraMojoChannelManager::GetInstance());
    std::unique_ptr<StillCaptureProcessor> still_capture_processor =
        std::make_unique<StillCaptureProcessorImpl>(std::move(jpeg_compressor));
    stream_manipulators_.emplace_back(EffectsStreamManipulator::Create(
        feature_profile.GetConfigFilePath(
            FeatureProfile::FeatureType::kEffects),
        runtime_options, std::move(still_capture_processor)));
    LOGF(INFO) << "EffectsStreamManipulator enabled";
  } else {
    LOGF(INFO) << "EffectsStreamManipulator not enabled";
  }
#else
  LOGF(INFO) << "Service built without effects support";
#endif

  // HDRnet must get frames without applying any other post-processing because
  // the ML inference needs pixel values in linear domain.
  MaybeEnableHdrNetStreamManipulator(feature_profile, create_options,
                                     gpu_resources, &stream_manipulators_);

  // TODO(jcliang): See if we want to move ZSL to feature profile.
  stream_manipulators_.emplace_back(std::make_unique<ZslStreamManipulator>());
  LOGF(INFO) << "ZslStreamManipulator enabled";

#if USE_CAMERA_FEATURE_DIAGNOSTICS
  stream_manipulators_.emplace_back(
      std::make_unique<FrameAnalysisStreamManipulator>(mojo_manager_token));
  LOGF(INFO) << "Frame analysis stream manipulator enabled";
#endif

  if (create_options.sw_privacy_switch_stream_manipulator_enabled) {
    stream_manipulators_.emplace_back(
        std::make_unique<SWPrivacySwitchStreamManipulator>(
            runtime_options, mojo_manager_token, gpu_resources));
    LOGF(INFO) << "SWPrivacySwitchStreamManipulator enabled";
  }
}

StreamManipulatorManager::StreamManipulatorManager(
    std::vector<std::unique_ptr<StreamManipulator>> stream_manipulators)
    : default_capture_result_thread_("DefaultCaptureResultThread") {
  CHECK(default_capture_result_thread_.Start());
  TRACE_COMMON();

  stream_manipulators_ = std::move(stream_manipulators);
}

StreamManipulatorManager::~StreamManipulatorManager() {
  // Wait for in-flight result processing to finish.
  if (!all_results_returned_.TimedWait(base::Milliseconds(300))) {
    LOGF(ERROR)
        << "Timed out waiting for in-flight result processing to finish";
  }

  // Destruct stream manipulators in the reverse order to ensure that
  // ProcessCaptureResultOnStreamManipulator() does not post tasks to destructed
  // stream manipulators.
  while (!stream_manipulators_.empty()) {
    stream_manipulators_.pop_back();
  }
}

bool StreamManipulatorManager::Initialize(
    const camera_metadata_t* static_info,
    StreamManipulator::Callbacks callbacks) {
  TRACE_COMMON();

  callbacks_ = std::move(callbacks);

  int partial_result_count = [&]() {
    camera_metadata_ro_entry entry;
    if (find_camera_metadata_ro_entry(
            static_info, ANDROID_REQUEST_PARTIAL_RESULT_COUNT, &entry) != 0) {
      return 1;
    }
    return entry.data.i32[0];
  }();
  camera_metadata_inspector_ =
      CameraMetadataInspector::Create(partial_result_count);

  if (stream_manipulators_.empty()) {
    return true;
  }

  stream_manipulators_[0]->Initialize(
      static_info, StreamManipulator::Callbacks{
                       .result_callback = base::BindRepeating(
                           &StreamManipulatorManager::ReturnResultToClient,
                           base::Unretained(this)),
                       .notify_callback = callbacks_.notify_callback});
  for (int i = 1; i < stream_manipulators_.size(); ++i) {
    stream_manipulators_[i]->Initialize(
        static_info,
        StreamManipulator::Callbacks{
            .result_callback =
                base::BindRepeating(&StreamManipulatorManager::
                                        ProcessCaptureResultOnStreamManipulator,
                                    base::Unretained(this), i - 1),
            .notify_callback = base::BindRepeating(
                &StreamManipulatorManager::NotifyOnStreamManipulator,
                base::Unretained(this), i - 1)});
  }
  return true;
}

bool StreamManipulatorManager::ConfigureStreams(
    Camera3StreamConfiguration* stream_config,
    const StreamEffectMap* stream_effects_map) {
  TRACE_COMMON();

  for (auto& stream_manipulator : stream_manipulators_) {
    stream_manipulator->ConfigureStreams(stream_config, stream_effects_map);
  }
  return true;
}

bool StreamManipulatorManager::OnConfiguredStreams(
    Camera3StreamConfiguration* stream_config) {
  TRACE_COMMON();

  // Call OnConfiguredStreams in reverse order so the stream manipulators can
  // unwind the stream modifications.
  for (auto it = stream_manipulators_.rbegin();
       it != stream_manipulators_.rend(); ++it) {
    (*it)->OnConfiguredStreams(stream_config);
  }
  return true;
}

bool StreamManipulatorManager::ConstructDefaultRequestSettings(
    android::CameraMetadata* default_request_settings, int type) {
  TRACE_COMMON();

  for (auto it = stream_manipulators_.rbegin();
       it != stream_manipulators_.rend(); ++it) {
    (*it)->ConstructDefaultRequestSettings(default_request_settings, type);
  }
  return true;
}

bool StreamManipulatorManager::ProcessCaptureRequest(
    Camera3CaptureDescriptor* request) {
  TRACE_COMMON("frame_number", request->frame_number());

  for (size_t i = 0; i < stream_manipulators_.size(); ++i) {
    if (camera_metadata_inspector_ &&
        camera_metadata_inspector_->IsPositionInspected(i)) {
      camera_metadata_inspector_->InspectRequest(request->LockForRequest(), i);
      request->Unlock();
    }
    TRACE_COMMON_EVENT("SM::ProcessCaptureRequest",
                       [&](perfetto::EventContext ctx) {
                         request->PopulateEventAnnotation(ctx);
                       });
    stream_manipulators_[i]->ProcessCaptureRequest(request);
  }
  if (camera_metadata_inspector_ &&
      camera_metadata_inspector_->IsPositionInspected(
          stream_manipulators_.size())) {
    camera_metadata_inspector_->InspectRequest(request->LockForRequest(),
                                               stream_manipulators_.size());
    request->Unlock();
  }
  return true;
}

bool StreamManipulatorManager::Flush() {
  TRACE_COMMON();

  for (auto it = stream_manipulators_.rbegin();
       it != stream_manipulators_.rend(); ++it) {
    (*it)->Flush();
  }
  return true;
}

void StreamManipulatorManager::ProcessCaptureResult(
    Camera3CaptureDescriptor result) {
  TRACE_COMMON("frame_number", result.frame_number());

  {
    base::AutoLock l(inflight_result_count_lock_);
    if (++inflight_result_count_ == 1) {
      all_results_returned_.Reset();
    }
  }

  if (stream_manipulators_.empty()) {
    ReturnResultToClient(std::move(result));
    return;
  }

  ProcessCaptureResultOnStreamManipulator(stream_manipulators_.size() - 1,
                                          std::move(result));
}

void StreamManipulatorManager::Notify(camera3_notify_msg_t msg) {
  TRACE_COMMON();

  if (stream_manipulators_.empty()) {
    callbacks_.notify_callback.Run(std::move(msg));
  } else {
    NotifyOnStreamManipulator(stream_manipulators_.size() - 1, std::move(msg));
  }
}

void StreamManipulatorManager::ProcessCaptureResultOnStreamManipulator(
    int stream_manipulator_index, Camera3CaptureDescriptor result) {
  TRACE_COMMON(
      [&](perfetto::EventContext ctx) { result.PopulateEventAnnotation(ctx); });

  DCHECK(0 <= stream_manipulator_index &&
         stream_manipulator_index < stream_manipulators_.size());
  InspectResult(stream_manipulator_index + 1, result);

  auto task_runner =
      stream_manipulators_[stream_manipulator_index]->GetTaskRunner();
  if (task_runner == nullptr) {
    task_runner = default_capture_result_thread_.task_runner();
  }
  task_runner->PostTask(
      FROM_HERE,
      base::BindOnce(
          base::IgnoreResult(&StreamManipulator::ProcessCaptureResult),
          base::Unretained(
              stream_manipulators_[stream_manipulator_index].get()),
          std::move(result)));
}

void StreamManipulatorManager::NotifyOnStreamManipulator(
    int stream_manipulator_index, camera3_notify_msg_t msg) {
  TRACE_COMMON();

  DCHECK(0 <= stream_manipulator_index &&
         stream_manipulator_index < stream_manipulators_.size());
  auto task_runner =
      stream_manipulators_[stream_manipulator_index]->GetTaskRunner();
  if (task_runner == nullptr) {
    task_runner = default_capture_result_thread_.task_runner();
  }
  task_runner->PostTask(
      FROM_HERE,
      base::BindOnce(base::IgnoreResult(&StreamManipulator::Notify),
                     base::Unretained(
                         stream_manipulators_[stream_manipulator_index].get()),
                     std::move(msg)));
}

void StreamManipulatorManager::ReturnResultToClient(
    Camera3CaptureDescriptor result) {
  TRACE_COMMON(
      [&](perfetto::EventContext ctx) { result.PopulateEventAnnotation(ctx); });

  DCHECK(!callbacks_.result_callback.is_null());
  InspectResult(0, result);
  callbacks_.result_callback.Run(std::move(result));

  base::AutoLock l(inflight_result_count_lock_);
  if (--inflight_result_count_ == 0) {
    all_results_returned_.Signal();
  }
}

void StreamManipulatorManager::InspectResult(int position,
                                             Camera3CaptureDescriptor& result) {
  DCHECK(0 <= position && position <= stream_manipulators_.size());
  if (camera_metadata_inspector_ &&
      camera_metadata_inspector_->IsPositionInspected(position)) {
    camera_metadata_inspector_->InspectResult(result.LockForResult(), position);
    result.Unlock();
  }
}

}  // namespace cros
