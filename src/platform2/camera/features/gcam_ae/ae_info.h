/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_FEATURES_GCAM_AE_AE_INFO_H_
#define CAMERA_FEATURES_GCAM_AE_AE_INFO_H_

#include <cstdint>
#include <optional>
#include <vector>

#include <base/files/scoped_file.h>
#include <base/notreached.h>
#include <cros-camera/gcam_ae.h>
#include <cutils/native_handle.h>

#include "camera/camera_metadata.h"
#include "cros-camera/common_types.h"

namespace cros {

// Tags for metadata logger.
constexpr char kTagActualTet[] = "actual_tet";
constexpr char kTagAeExposureCompensation[] = "ae_exposure_compensation";
constexpr char kTagAeState[] = "ae_state";
constexpr char kTagAwbGains[] = "awb_rggb_gains";
constexpr char kTagCaptureAnalogGain[] = "analog_gain";
constexpr char kTagCaptureDigitalGain[] = "digital_gain";
constexpr char kTagCaptureExposureTimeNs[] = "exposure_time_ns";
constexpr char kTagCaptureSensitivity[] = "sensitivity";
constexpr char kTagCcm[] = "ccm";
constexpr char kTagEstimatedSensorSensitivity[] =
    "estimated_sensor_sensitivity";
constexpr char kTagFaceRectangles[] = "face_rectangles";
constexpr char kTagFilteredLongTet[] = "filtered_long_tet";
constexpr char kTagFilteredShortTet[] = "filtered_short_tet";
constexpr char kTagFrameHeight[] = "frame_height";
constexpr char kTagFrameWidth[] = "frame_width";
constexpr char kTagHdrRatio[] = "hdr_ratio";
constexpr char kTagIpu6RgbsStatsBlocks[] = "ipu6.ae_stats.blocks";
constexpr char kTagIpu6RgbsStatsGridHeight[] = "ipu6.ae_stats.grid_height";
constexpr char kTagIpu6RgbsStatsGridWidth[] = "ipu6.ae_stats.grid_width";
constexpr char kTagIpu6RgbsStatsShadingCorrection[] =
    "ipu6.ae_stats.shading_correction";
constexpr char kTagIpu6TetRange[] = "ipu6.total_exposure_target_range";
constexpr char kTagLensAperture[] = "lens_aperture";
constexpr char kTagLogSceneBrightness[] = "log_scene_brightness";
constexpr char kTagLongTet[] = "long_tet";
constexpr char kTagMaxHdrRatio[] = "max_hdr_ratio";
constexpr char kTagRequestAeCompensation[] = "request.ae_compensation";
constexpr char kTagRequestExpTime[] = "request.exposure_time_ns";
constexpr char kTagRequestSensitivity[] = "request.sensitivity";
constexpr char kTagShortTet[] = "short_tet";
constexpr char kTagToneMapCurve[] = "tonemap_curve";
constexpr char kTagWhiteLevel[] = "white_level";

// AeStatsInput is used to specify how Gcam AE computes the AE stats input to
// the AE algorithm.
enum class AeStatsInputMode {
  // Use vendor's AE stats to prepare AE algorithm input parameters.
  kFromVendorAeStats = 0,

  // Use YUV image to prepare AE algorithm input parameters.
  kFromYuvImage = 1,
};

enum class AeOverrideMode {
  // 0 is reserved for the deprecated kWithExposureCompensation to keep backward
  // compatibility.

  // Let GcamAeController override AE decision with manual sensor control.
  kWithManualSensorControl = 1,

  // Let GcamAeController override AE decision by passing the exposure target in
  // vendor-specific metadata to the vendor camera HAL.
  kWithVendorTag = 2,
};

// A collection of all the info needed for producing the input arguments to the
// AE algorithm.
struct AeFrameInfo {
  int frame_number = -1;
  AeStatsInputMode ae_stats_input_mode = AeStatsInputMode::kFromVendorAeStats;
  Size active_array_dimension;

  // The input parameters for Gcam AE.
  float target_tet = 0.0f;
  float target_hdr_ratio = 0.0f;
  // Base AE compensation in log2 space as configured in the Gcam AE config.
  // This is used as a IQ tuning parameter to control the overall frame
  // brightness and is agnostic to the camera client.
  float base_ae_compensation_log2 = 0.0f;
  // Client-requested AE compensation in log2 space. This is converted from the
  // AE compensation metadata and the AE compensation step from the client
  // request settings.
  float client_ae_compensation_log2 = 0.0f;
  Range<int> target_fps_range = {15, 30};

  // The capture result metadata describing how the frame was captured.
  float analog_gain = 0.0f;
  float digital_gain = 0.0f;
  float exposure_time_ms = 0.0f;
  // The AE compensation value in steps that was applied to capture the frame.
  int ae_compensation = 0;
  float estimated_sensor_sensitivity = 0.0f;
  std::optional<std::vector<NormalizedRect>> faces;

  // The capture request settings the camera client requested.
  struct {
    std::optional<uint8_t> ae_mode;
    // The AE compensation value in steps.
    std::optional<int32_t> ae_exposure_compensation;
    std::optional<uint8_t> ae_lock;
    std::optional<uint8_t> ae_antibanding_mode;
  } client_request_settings;

  // The AWB gains and color correction matrix that will be applied to the
  // frame.
  float rggb_gains[4] = {0};
  float ccm[9] = {0};

  // The YUV buffer of the frame and the acquire fence of the YUV buffer.
  buffer_handle_t yuv_buffer = nullptr;
  base::ScopedFD acquire_fence;

  bool HasCaptureSettings() const {
    return exposure_time_ms > 0.0f && analog_gain > 0.0f &&
           digital_gain > 0.0f && estimated_sensor_sensitivity > 0.0f;
  }

  bool HasYuvBuffer() const { return yuv_buffer != nullptr; }

  bool HasFaceInfo() const {
    // It's okay if there's no face detected.
    return faces.has_value();
  }

  bool IsValid() const {
    switch (ae_stats_input_mode) {
      case AeStatsInputMode::kFromVendorAeStats:
        // Face detector may need to wait for the YUV buffer.
        return HasCaptureSettings() && HasFaceInfo();
      case AeStatsInputMode::kFromYuvImage:
        return HasCaptureSettings() && HasFaceInfo() && HasYuvBuffer();
      default:
        NOTREACHED() << "Invalid AeStatsInputMode";
        return false;
    }
  }
};

struct AeParameters {
  // The Total Exposure Time (TET) that should be applied to the sensor for
  // capturing the image.
  float short_tet = 0.0f;

  // The ideal exposure time for HDR rendition.
  float long_tet = 0.0f;

  // The log scene brightness as computed by Gcam AE.
  float log_scene_brightness = kLogSceneBrightnessUnknown;

  // The usable TET range that |short_tet| and |long_tet| are computed with.
  Range<float> tet_range = {0.1f, 10.0e6f};

  bool IsValid() { return short_tet > 0.0f && long_tet > 0.0f; }
};

}  // namespace cros

#endif  // CAMERA_FEATURES_GCAM_AE_AE_INFO_H_
