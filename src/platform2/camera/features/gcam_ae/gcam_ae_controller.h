/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_GCAM_AE_GCAM_AE_CONTROLLER_H_
#define CAMERA_FEATURES_GCAM_AE_GCAM_AE_CONTROLLER_H_

#include <memory>
#include <optional>

#include <base/files/scoped_file.h>
#include <cutils/native_handle.h>
#include <system/camera_metadata.h>

#include "common/camera_hal3_helpers.h"
#include "features/gcam_ae/ae_info.h"
#include "features/gcam_ae/gcam_ae_device_adapter.h"

namespace cros {

// An interface class to facilitate testing.  For the actual GcamAeController
// implementation, see features/gcam_ae/gcam_ae_controller_impl.{h,cc}.
class GcamAeController {
 public:
  // A callback to cache the last TET value before destruction.
  struct CachedSettings {
    float last_tet = 1.0f;
    float last_hdr_ratio = 1.0f;
  };
  using DestructionCallback = base::OnceCallback<void(CachedSettings settings)>;

  using Factory = base::RepeatingCallback<std::unique_ptr<GcamAeController>(
      const camera_metadata_t* static_info,
      DestructionCallback destruction_callback)>;

  struct Options {
    // Whether the GcamAeController is enabled.
    bool enabled = false;

    // The duty cycle of the GcamAeController. The AE controller will
    // calculate and update AE parameters once every |ae_frame_interval| frames.
    int ae_frame_interval = 2;

    // A map with (gain, max_hdr_ratio) entries defining the max HDR ratio
    // passed to Gcam AE based on the gain (analog * digital) used to capture
    // the frame.
    base::flat_map<float, float> max_hdr_ratio = {{1.0, 5.0},  {2.0, 5.0},
                                                  {4.0, 5.0},  {8.0, 4.0},
                                                  {16.0, 2.0}, {32.0, 1.1}};

    // Controls how Gcam AE gets the AE stats input parameters.
    AeStatsInputMode ae_stats_input_mode = AeStatsInputMode::kFromVendorAeStats;

    // Controls how GcamAeController overrides camera HAL's AE decision.
    AeOverrideMode ae_override_mode = AeOverrideMode::kWithManualSensorControl;

    // The exposure compensation in stops set to every capture request.
    float exposure_compensation = 0.0f;

    // A multiplier applied to the gain calculated from the sensor sensitivity
    // and the sensitivity range metadata. This should be kept at 1.0 and should
    // not be changed unless the minimum sensitivity doesn't correspond to 1.0
    // gain.
    float gain_multiplier = 1.0f;
  };

  virtual ~GcamAeController() = default;

  // Records the YUV frame of |frame_number| provided in |buffer|.
  // |acquire_fence| is the fence that, if valid, needs to be synced on before
  // accessing |buffer|.  The YUV buffer is normally used for face detection
  // and/or compute the AE stats input to Gcam AE.
  virtual void RecordYuvBuffer(int frame_number,
                               buffer_handle_t buffer,
                               base::ScopedFD acquire_fence) = 0;

  // Records the AE metadata from capture result |result|.  The implementation
  // should use this method to capture the metadata needed for their AE
  // algorithm.
  virtual void RecordAeMetadata(Camera3CaptureDescriptor* result) = 0;

  // Callback for new options |json_values| in JSON format. |metadata_logger|,
  // if set, triggers logging per-frame metadata.
  virtual void OnOptionsUpdated(
      const base::Value::Dict& json_values,
      std::optional<MetadataLogger*> metadata_logger) = 0;

  // Gets the HDR ratio calculated by Gcam AE.  This is normally used to get the
  // input argument to the HDRnet processing pipeline.
  virtual std::optional<float> GetCalculatedHdrRatio(int frame_number) = 0;

  // Sets the AE parameters calculated by the AE algorithm in the capture
  // request |request|.
  virtual void SetRequestAeParameters(Camera3CaptureDescriptor* request) = 0;

  // Sets the face metadata in the capture result metadata in |result|.
  virtual void SetResultAeMetadata(Camera3CaptureDescriptor* result) = 0;
};

}  // namespace cros

#endif  // CAMERA_FEATURES_GCAM_AE_GCAM_AE_CONTROLLER_H_
