/*
 * Copyright 2023 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_ROTATE_AND_CROP_ROTATE_AND_CROP_STREAM_MANIPULATOR_H_
#define CAMERA_FEATURES_ROTATE_AND_CROP_ROTATE_AND_CROP_STREAM_MANIPULATOR_H_

#include <hardware/camera3.h>

#include <map>
#include <memory>
#include <set>

#include <base/containers/flat_set.h>

#include "common/camera_buffer_pool.h"
#include "common/still_capture_processor.h"
#include "common/stream_manipulator.h"
#include "features/rotate_and_crop/resizable_cpu_buffer.h"

namespace cros {

// This StreamManipulator implements the ANDROID_SCALER_ROTATE_AND_CROP API
// introduced since Android T, and adapts to the legacy
// |camera3_stream_t::crop_rotate_scale_degrees| API that was added in ARC-P/R
// for camera app orientation compatibility (inset-portrait mode).  Depending on
// the HAL reported ANDROID_SCALER_AVAILABLE_ROTATE_AND_CROP_MODES and the
// client ARC version, it does:
//
//   HAL modes  ARC ver.  RotateAndCropSM behavior
//   ---------------------------------------------------------------------------
//   null       P, R      Bypass crop_rotate_scale_degrees
//              T         Do rotation with ROTATE_AND_CROP
//   NONE       P, R      Do rotation with crop_rotate_scale_degrees
//              T         Do rotation with ROTATE_AND_CROP
//   > NONE     P, R      Translate crop_rotate_scale_degrees to ROTATE_AND_CROP
//              T         Bypass ROTATE_AND_CROP
//
// The HAL always receive non-AUTO value resolved by the RotateAndCropSM.
//
// The client ARC version can be distinguished by:
// - P/R: ConfigureStreams() may receive non-zero |crop_rotate_scale_degrees|.
//   and ProcessCaptureRequest() receives null or AUTO ROTATE_AND_CROP mode.
// - T: ProcessCaptureRequest() receives non-AUTO ROTATE_AND_CROP mode.
//
// TODO(b/130311697): Android P/R clients don't know the ROTATE_AND_CROP
// metadata. We assume they don't touch the default ROTATE_AND_CROP value (AUTO)
// in the default request settings, or don't send it in request metadata. See if
// we can remove this assumption to meet Android API contract.
//
class RotateAndCropStreamManipulator : public StreamManipulator {
 public:
  explicit RotateAndCropStreamManipulator(
      std::unique_ptr<StillCaptureProcessor> still_capture_processor);
  ~RotateAndCropStreamManipulator() override;

  static bool UpdateVendorTags(VendorTagManager& vendor_tag_manager);
  static bool UpdateStaticMetadata(android::CameraMetadata* static_info);

  // Implementations of StreamManipulator.
  bool Initialize(const camera_metadata_t* static_info,
                  Callbacks callbacks) override;
  bool ConfigureStreams(Camera3StreamConfiguration* stream_config,
                        const StreamEffectMap* stream_effects_map) override;
  bool OnConfiguredStreams(Camera3StreamConfiguration* stream_config) override;
  bool ConstructDefaultRequestSettings(
      android::CameraMetadata* default_request_settings, int type) override;
  bool ProcessCaptureRequest(Camera3CaptureDescriptor* request) override;
  bool ProcessCaptureResult(Camera3CaptureDescriptor result) override;
  void Notify(camera3_notify_msg_t msg) override;
  bool Flush() override;

 private:
  bool InitializeOnThread(const camera_metadata_t* static_info,
                          Callbacks callbacks);
  bool ConfigureStreamsOnThread(Camera3StreamConfiguration* stream_config);
  bool OnConfiguredStreamsOnThread(Camera3StreamConfiguration* stream_config);
  bool ProcessCaptureRequestOnThread(Camera3CaptureDescriptor* request);
  bool ProcessCaptureResultOnThread(Camera3CaptureDescriptor result);
  void ResetOnThread();
  void ReturnStillCaptureResultOnThread(Camera3CaptureDescriptor result);
  bool RotateAndCropOnThread(buffer_handle_t buffer,
                             base::ScopedFD release_fence,
                             uint8_t rc_mode);

  struct CaptureContext {
    uint8_t client_rc_mode = 0;
    uint8_t hal_rc_mode = 0;
    uint32_t num_pending_buffers = 0;
    bool metadata_received = false;
    bool has_pending_blob = false;
    std::optional<CameraBufferPool::Buffer> yuv_buffer;
    bool yuv_stream_appended = false;
  };

  std::unique_ptr<StillCaptureProcessor> still_capture_processor_;

  // Fixed after Initialize().
  base::flat_set<uint8_t> hal_available_rc_modes_;
  uint32_t partial_result_count_ = 0;
  Callbacks callbacks_;

  // Per-stream-config context.
  int client_crs_degrees_ = 0;
  const camera3_stream_t* blob_stream_ = nullptr;
  std::optional<camera3_stream_t> yuv_stream_for_blob_owned_;
  camera3_stream_t* yuv_stream_for_blob_ = nullptr;
  std::unique_ptr<CameraBufferPool> yuv_buffer_pool_;
  ResizableCpuBuffer buffer1_, buffer2_;
  base::flat_map<uint32_t, CaptureContext> capture_contexts_;

  CameraThread thread_;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_ROTATE_AND_CROP_ROTATE_AND_CROP_STREAM_MANIPULATOR_H_
