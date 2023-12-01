/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_AUTO_FRAMING_AUTO_FRAMING_STREAM_MANIPULATOR_H_
#define CAMERA_FEATURES_AUTO_FRAMING_AUTO_FRAMING_STREAM_MANIPULATOR_H_

#include "common/stream_manipulator.h"

#include <map>
#include <memory>
#include <utility>
#include <vector>

#include <base/containers/flat_map.h>
#include <base/time/time.h>
#include <base/timer/elapsed_timer.h>

#include "common/camera_buffer_pool.h"
#include "common/camera_hal3_helpers.h"
#include "common/reloadable_config_file.h"
#include "common/still_capture_processor.h"
#include "cros-camera/camera_metrics.h"
#include "cros-camera/common_types.h"
#include "features/auto_framing/auto_framing_client.h"

namespace cros {

class AutoFramingStreamManipulator : public StreamManipulator {
 public:
  // The auto framing config file that overrides the default one for debugging.
  // The file should contain a JSON map for the Options defined below.
  static constexpr const char kOverrideAutoFramingConfigFile[] =
      "/run/camera/auto_framing_config.json";

  struct Options {
    // Max video stream size that output frames are cropped/scaled from.
    std::optional<uint32_t> max_video_width;
    std::optional<uint32_t> max_video_height;

    // The filtering algorithm to scale the cropped region into output frames.
    FilterMode output_filter_mode = FilterMode::kBicubic;

    // Number of frames per second to run detection. The actual rate is capped
    // by the detection speed. Setting zero means one-shot detection for each
    // auto-framing enabled period.
    float detection_rate = 0.0f;

    // Delay when enabling auto-framing.
    base::TimeDelta enable_delay = base::Seconds(0.5);

    // Delay when disabling auto-framing.
    base::TimeDelta disable_delay = base::Seconds(0.5);

    // Whether the CrOS Auto Framing is enabled.
    std::optional<bool> enable;

    // Whether to enable debug mode. In debug mode the frame is not cropped.
    // Instead the ROIs and active crop area is piggybacked in the
    // FACE_RECTANGLES metadata and we can use Chrome Camera App to visualize
    // the auto-framing transition.
    bool debug = false;
  };

  AutoFramingStreamManipulator(
      RuntimeOptions* runtime_options,
      GpuResources* gpu_resources,
      base::FilePath config_file_path,
      std::unique_ptr<StillCaptureProcessor> still_capture_processor,
      std::optional<Options> options_override_for_testing = std::nullopt);
  ~AutoFramingStreamManipulator() override;

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

  // For testing.
  const Rect<float>& region_of_interest() const { return region_of_interest_; }
  const Rect<float>& active_crop_region() const { return active_crop_region_; }

 private:
  struct CaptureContext;

  enum class State {
    // Auto-framing is disabled completely. In this state this SM is no-op.
    kDisabled,
    // Auto-framing is turned off. Settles the crop window to the full image.
    kOff,
    // The intermediate state before transitioning to |kOn| state.
    kTransitionToOn,
    // The state when auto-framing is turned on. Moves the crop window
    // continuously based on the detection rate.
    kOn,
    // The intermediate state before transitioning to |kOff| state.
    kTransitionToOff,
  };

  struct Metrics {
    int num_captures = 0;
    int enabled_count = 0;
    base::TimeDelta accumulated_on_time = base::Seconds(0);
    base::TimeDelta accumulated_off_time = base::Seconds(0);
    base::flat_map<AutoFramingError, int> errors;
  };

  bool InitializeOnThread(const camera_metadata_t* static_info,
                          StreamManipulator::Callbacks callbacks);
  bool ConfigureStreamsOnThread(Camera3StreamConfiguration* stream_config);
  bool OnConfiguredStreamsOnThread(Camera3StreamConfiguration* stream_config);
  bool ProcessCaptureRequestOnThread(Camera3CaptureDescriptor* request);
  bool ProcessCaptureResultOnThread(Camera3CaptureDescriptor* result);

  bool SetUpPipelineOnThread(uint32_t target_aspect_ratio_x,
                             uint32_t target_aspect_ratio_y);
  bool ProcessFullFrameOnThread(CaptureContext* ctx,
                                Camera3StreamBuffer full_frame_buffer,
                                uint32_t frame_number);
  bool ProcessStillYuvOnThread(CaptureContext* ctx,
                               Camera3StreamBuffer still_yuv_buffer,
                               uint32_t frame_number);
  void ReturnStillCaptureResultOnThread(Camera3CaptureDescriptor result);
  void UpdateFaceRectangleMetadataOnThread(Camera3CaptureDescriptor* result);
  void ResetOnThread();
  void UpdateOptionsOnThread(const base::Value::Dict& json_values);
  std::pair<State, State> StateTransitionOnThread();
  void UploadMetricsOnThread();

  void OnOptionsUpdated(const base::Value::Dict& json_values);

  CaptureContext* CreateCaptureContext(uint32_t frame_number);
  CaptureContext* GetCaptureContext(uint32_t frame_number) const;
  void RemoveCaptureContext(uint32_t frame_number);

  // Crops |input_yuv| into |output_yuv| with the |crop_region|.  Returns
  // release fence on the output buffer, or nullopt if there's failure.
  std::optional<base::ScopedFD> CropBufferOnThread(
      buffer_handle_t input_yuv,
      base::ScopedFD input_fence,
      buffer_handle_t output_yuv,
      base::ScopedFD output_fence,
      const Rect<float>& crop_region);

  bool GetEnabled();

  ReloadableConfigFile config_;

  Options options_;

  RuntimeOptions* runtime_options_;
  GpuResources* gpu_resources_ = nullptr;
  std::unique_ptr<StillCaptureProcessor> still_capture_processor_;
  StreamManipulator::Callbacks callbacks_;

  std::unique_ptr<CameraMetrics> camera_metrics_;

  // Determined by static camera metadata and fixed after Initialize().
  Size active_array_dimension_;
  Size full_frame_size_;
  Size still_size_;
  Rect<float> full_frame_crop_;
  int partial_result_count_ = 0;

  // Flagged if any failure during Initialize() and ConfigureStreams() that
  // disables auto-framing processing.
  bool setup_failed_ = false;

  // Per-stream-config contexts.
  State state_ = State::kDisabled;
  base::ElapsedTimer state_transition_timer_;
  std::vector<camera3_stream_t*> client_streams_;
  camera3_stream_t full_frame_stream_ = {};
  const camera3_stream_t* blob_stream_ = nullptr;
  std::unique_ptr<camera3_stream_t> still_yuv_stream_;
  const camera3_stream_t* yuv_stream_for_blob_ = nullptr;
  std::map<uint32_t, std::unique_ptr<CaptureContext>> capture_contexts_;
  int64_t last_timestamp_ = 0;
  int64_t timestamp_offset_ = 0;

  AutoFramingClient auto_framing_client_;
  std::unique_ptr<CameraBufferPool> full_frame_buffer_pool_;
  std::unique_ptr<CameraBufferPool> still_yuv_buffer_pool_;
  std::unique_ptr<CameraBufferPool> cropped_still_yuv_buffer_pool_;

  std::vector<Rect<float>> faces_;
  Rect<float> region_of_interest_ = {0.0f, 0.0f, 1.0f, 1.0f};
  Rect<float> active_crop_region_ = {0.0f, 0.0f, 1.0f, 1.0f};

  Metrics metrics_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_AUTO_FRAMING_AUTO_FRAMING_STREAM_MANIPULATOR_H_
