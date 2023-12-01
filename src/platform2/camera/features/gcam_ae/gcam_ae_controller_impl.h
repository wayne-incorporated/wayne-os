/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_GCAM_AE_GCAM_AE_CONTROLLER_IMPL_H_
#define CAMERA_FEATURES_GCAM_AE_GCAM_AE_CONTROLLER_IMPL_H_

#include "features/gcam_ae/gcam_ae_controller.h"

#include <array>
#include <memory>
#include <optional>
#include <vector>

#include <base/sequence_checker.h>

#include "common/metadata_logger.h"
#include "cros-camera/common_types.h"
#include "cros-camera/timezone.h"
#include "features/gcam_ae/ae_state_machine.h"

namespace cros {

class GcamAeControllerImpl : public GcamAeController {
 public:
  // The default factory method to get the activated GcamAeController
  // instance.
  static std::unique_ptr<GcamAeController> CreateInstance(
      const camera_metadata_t* static_info,
      DestructionCallback destruction_callback);

  GcamAeControllerImpl(const camera_metadata_t* static_info,
                       std::unique_ptr<GcamAeDeviceAdapter> ae_device_adapter,
                       DestructionCallback destruction_callback);

  // GcamAeController implementations.
  ~GcamAeControllerImpl() override;
  void RecordYuvBuffer(int frame_number,
                       buffer_handle_t buffer,
                       base::ScopedFD acquire_fence) override;
  void RecordAeMetadata(Camera3CaptureDescriptor* result) override;
  void OnOptionsUpdated(
      const base::Value::Dict& json_values,
      std::optional<MetadataLogger*> metadata_logger) override;
  std::optional<float> GetCalculatedHdrRatio(int frame_number) override;
  void SetRequestAeParameters(Camera3CaptureDescriptor* request) override;
  void SetResultAeMetadata(Camera3CaptureDescriptor* result) override;

 private:
  void MaybeRunAE(int frame_number);

  // Records the capture settings requested by the camera client, so that we can
  // restore them in the capture result.
  void RecordClientRequestSettings(const Camera3CaptureDescriptor* request);
  // Restores the settings to what the client originally requested.
  void RestoreClientRequestSettings(Camera3CaptureDescriptor* result);

  void SetManualSensorControls(Camera3CaptureDescriptor* request);

  // Internal helper methods.
  bool ShouldRunAe(int frame_number) const;
  bool ShouldRunFd(int frame_number) const;
  bool ShouldRecordYuvBuffer(int frame_number) const;

  AeFrameInfo* CreateAeFrameInfoEntry(int frame_number);
  AeFrameInfo* GetAeFrameInfoEntry(int frame_number);

  Options options_;
  DestructionCallback destruction_callback_;

  // AE loop controls.
  AeStateMachine ae_state_machine_;

  // Device static metadata.
  Range<int> sensitivity_range_;
  int max_analog_sensitivity_;
  float max_analog_gain_;
  float max_total_gain_;
  float ae_compensation_step_;
  Range<float> ae_compensation_range_;
  Size active_array_dimension_;
  v4l2_power_line_frequency powerline_freq_;

  // Ring buffer for the per-frame AE metadata.
  static constexpr size_t kAeFrameInfoRingBufferSize = 12;
  std::array<AeFrameInfo, kAeFrameInfoRingBufferSize> frame_info_;

  // Device-specific AE adapter that handles AE stats extraction and AE
  // parameters computation.
  std::unique_ptr<GcamAeDeviceAdapter> ae_device_adapter_;

  // Metadata logger for tests and debugging.
  MetadataLogger* metadata_logger_ = nullptr;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_GCAM_AE_GCAM_AE_CONTROLLER_IMPL_H_
