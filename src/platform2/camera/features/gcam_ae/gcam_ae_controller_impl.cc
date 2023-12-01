/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "features/gcam_ae/gcam_ae_controller_impl.h"

#include <algorithm>
#include <cmath>
#include <optional>
#include <tuple>
#include <utility>

#include <base/strings/string_number_conversions.h>

#include "common/reloadable_config_file.h"
#include "cros-camera/camera_buffer_manager.h"
#include "cros-camera/camera_metadata_utils.h"
#include "cros-camera/common.h"
#include "cros-camera/tracing.h"
#include "features/gcam_ae/tracing.h"

#if USE_CAMERA_FEATURE_FACE_DETECTION
#include "cros-camera/face_detector_client_cros_wrapper.h"
#endif

namespace cros {

namespace {

constexpr char kAeFrameIntervalKey[] = "ae_frame_interval";
constexpr char kAeOverrideModeKey[] = "ae_override_mode";
constexpr char kAeStatsInputModeKey[] = "ae_stats_input_mode";
constexpr char kExposureCompensationKey[] = "exp_comp";
constexpr char kGcamAeEnableKey[] = "gcam_ae_enable";
constexpr char kMaxHdrRatioKey[] = "max_hdr_ratio";
constexpr char kGainMultiplier[] = "gain_multiplier";

float LookUpHdrRatio(const base::flat_map<float, float>& max_hdr_ratio,
                     float gain) {
  DCHECK(!max_hdr_ratio.empty());
  for (auto it = max_hdr_ratio.rbegin(); it != max_hdr_ratio.rend(); it++) {
    if (it->first <= gain) {
      auto prev = (it == max_hdr_ratio.rbegin()) ? it : it - 1;
      const float min_gain = it->first;
      const float min_ratio = it->second;
      const float max_gain = prev->first;
      const float max_ratio = prev->second;
      const float slope = (max_ratio - min_ratio) / (max_gain - min_gain);
      return min_ratio + slope * (gain - min_gain);
    }
  }
  // Default to the HDR ratio at the maximum gain, which is usually the smallest
  // one.
  return max_hdr_ratio.rbegin()->second;
}

bool IsClientManualSensorControlSet(const AeFrameInfo& frame_info) {
  if (frame_info.client_request_settings.ae_mode &&
      frame_info.client_request_settings.ae_mode.value() ==
          ANDROID_CONTROL_AE_MODE_OFF) {
    return true;
  }
  return false;
}

#if USE_CAMERA_FEATURE_FACE_DETECTION
std::vector<NormalizedRect> CrosFaceToNormalizedRect(
    const std::vector<human_sensing::CrosFace>& faces,
    const Size& active_array_dimension) {
  std::vector<NormalizedRect> result;
  for (const auto& f : faces) {
    result.push_back(NormalizedRect{
        .x0 = f.bounding_box.x1 / active_array_dimension.width,
        .x1 = f.bounding_box.x2 / active_array_dimension.width,
        .y0 = f.bounding_box.y1 / active_array_dimension.height,
        .y1 = f.bounding_box.y2 / active_array_dimension.height});
  }
  return result;
}
#endif

}  // namespace

// static
std::unique_ptr<GcamAeController> GcamAeControllerImpl::CreateInstance(
    const camera_metadata_t* static_info,
    DestructionCallback destruction_callback) {
  return std::make_unique<GcamAeControllerImpl>(
      static_info, GcamAeDeviceAdapter::CreateInstance(),
      std::move(destruction_callback));
}

GcamAeControllerImpl::GcamAeControllerImpl(
    const camera_metadata_t* static_info,
    std::unique_ptr<GcamAeDeviceAdapter> ae_device_adapter,
    DestructionCallback destruction_callback)
    : destruction_callback_(std::move(destruction_callback)),
      ae_device_adapter_(std::move(ae_device_adapter)) {
  base::span<const int32_t> sensitivity_range = GetRoMetadataAsSpan<int32_t>(
      static_info, ANDROID_SENSOR_INFO_SENSITIVITY_RANGE);
  std::optional<int32_t> max_analog_sensitivity = GetRoMetadata<int32_t>(
      static_info, ANDROID_SENSOR_MAX_ANALOG_SENSITIVITY);
  std::optional<Rational> ae_compensation_step = GetRoMetadata<Rational>(
      static_info, ANDROID_CONTROL_AE_COMPENSATION_STEP);
  base::span<const int32_t> ae_compensation_range =
      GetRoMetadataAsSpan<int32_t>(static_info,
                                   ANDROID_CONTROL_AE_COMPENSATION_RANGE);
  base::span<const int32_t> active_array_size = GetRoMetadataAsSpan<int32_t>(
      static_info, ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE);

  DCHECK_EQ(sensitivity_range.size(), 2);
  DCHECK_NE(sensitivity_range[0], 0);
  DCHECK(max_analog_sensitivity);
  DCHECK(ae_compensation_step);
  DCHECK_NE(ae_compensation_step->denominator, 0);
  DCHECK_EQ(ae_compensation_range.size(), 2);
  DCHECK_EQ(active_array_size.size(), 4);

  VLOGF(2) << "sensitivity_range: " << sensitivity_range[0] << " - "
           << sensitivity_range[1];
  VLOGF(2) << "max_analog_sensitivity: " << *max_analog_sensitivity;
  VLOGF(2) << "ae_compensation_step: " << ae_compensation_step->numerator << "/"
           << ae_compensation_step->denominator;
  VLOGF(2) << "ae_compensation_range: " << ae_compensation_range[0] << " - "
           << ae_compensation_range[1];
  VLOGF(2) << "active_array_size: (" << active_array_size[0] << ", "
           << active_array_size[1] << "), (" << active_array_size[2] << ", "
           << active_array_size[3] << ")";

  sensitivity_range_ = Range<int>(sensitivity_range[0], sensitivity_range[1]);
  max_analog_sensitivity_ = *max_analog_sensitivity;
  max_analog_gain_ = options_.gain_multiplier *
                     (static_cast<float>(max_analog_sensitivity_) /
                      static_cast<float>(sensitivity_range_.lower()));
  max_total_gain_ = options_.gain_multiplier *
                    (static_cast<float>(sensitivity_range_.upper()) /
                     static_cast<float>(sensitivity_range_.lower()));
  ae_compensation_step_ =
      (static_cast<float>(ae_compensation_step->numerator) /
       static_cast<float>(ae_compensation_step->denominator));
  ae_compensation_range_ =
      Range<float>(static_cast<float>(ae_compensation_range[0]),
                   static_cast<float>(ae_compensation_range[1]));
  active_array_dimension_ = Size(active_array_size[2], active_array_size[3]);

  powerline_freq_ = GetPowerLineFrequencyForLocation().value_or(
      V4L2_CID_POWER_LINE_FREQUENCY_DISABLED);
}

GcamAeControllerImpl::~GcamAeControllerImpl() {
  DCHECK(!destruction_callback_.is_null());
  std::move(destruction_callback_)
      .Run({
          .last_tet = std::max(ae_state_machine_.GetCaptureTet(), 1.0f),
          .last_hdr_ratio =
              std::max(ae_state_machine_.GetFilteredHdrRatio(), 1.0f),
      });
}

void GcamAeControllerImpl::RecordYuvBuffer(int frame_number,
                                           buffer_handle_t buffer,
                                           base::ScopedFD acquire_fence) {
  if (options_.ae_stats_input_mode != AeStatsInputMode::kFromYuvImage) {
    return;
  }
  AeFrameInfo* frame_info = GetAeFrameInfoEntry(frame_number);
  if (!frame_info) {
    return;
  }
  frame_info->yuv_buffer = buffer;
  frame_info->acquire_fence = std::move(acquire_fence);
  MaybeRunAE(frame_number);
}

void GcamAeControllerImpl::RecordAeMetadata(Camera3CaptureDescriptor* result) {
  AeFrameInfo* frame_info = GetAeFrameInfoEntry(result->frame_number());
  if (!frame_info) {
    return;
  }

  // Exposure and gain info.
  base::span<const int32_t> sensitivity =
      result->GetMetadata<int32_t>(ANDROID_SENSOR_SENSITIVITY);
  if (sensitivity.empty()) {
    LOGF(WARNING) << "Cannot get ANDROID_SENSOR_SENSITIVITY";
    return;
  }
  base::span<const int64_t> exposure_time_ns =
      result->GetMetadata<int64_t>(ANDROID_SENSOR_EXPOSURE_TIME);
  if (exposure_time_ns.empty()) {
    LOGF(WARNING) << "Cannot get ANDROID_SENSOR_EXPOSURE_TIME";
    return;
  }
  base::span<const float> aperture =
      result->GetMetadata<float>(ANDROID_LENS_APERTURE);
  if (aperture.empty()) {
    LOGF(WARNING) << "Cannot get ANDROID_LENS_APERTURE";
    return;
  }
  base::span<const int32_t> ae_compensation =
      result->GetMetadata<int32_t>(ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION);
  if (ae_compensation.empty()) {
    LOGF(WARNING) << "Cannot get ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION";
    return;
  }
  if (static_cast<float>(ae_compensation[0]) < ae_compensation_range_.lower() ||
      static_cast<float>(ae_compensation[0]) > ae_compensation_range_.upper()) {
    LOGFID(WARNING, result->frame_number())
        << "Invalid AE compensation value: " << ae_compensation[0];
    return;
  }

  float total_gain = options_.gain_multiplier *
                     (base::checked_cast<float>(sensitivity[0]) /
                      static_cast<float>(sensitivity_range_.lower()));
  float analog_gain = std::min(total_gain, max_analog_gain_);
  float digital_gain = std::max(total_gain / max_analog_gain_, 1.0f);

  frame_info->exposure_time_ms =
      base::checked_cast<float>(exposure_time_ns[0]) / 1'000'000;
  frame_info->analog_gain = analog_gain;
  frame_info->digital_gain = digital_gain;
  frame_info->estimated_sensor_sensitivity =
      (base::checked_cast<float>(sensitivity_range_.lower()) /
       (aperture[0] * aperture[0]));
  frame_info->ae_compensation = ae_compensation[0];

  if (metadata_logger_) {
    metadata_logger_->Log(result->frame_number(), kTagCaptureExposureTimeNs,
                          exposure_time_ns[0]);
    metadata_logger_->Log(result->frame_number(), kTagCaptureSensitivity,
                          sensitivity[0]);
    metadata_logger_->Log(result->frame_number(), kTagCaptureAnalogGain,
                          analog_gain);
    metadata_logger_->Log(result->frame_number(), kTagCaptureDigitalGain,
                          digital_gain);
    metadata_logger_->Log(result->frame_number(),
                          kTagEstimatedSensorSensitivity,
                          frame_info->estimated_sensor_sensitivity);
    metadata_logger_->Log(result->frame_number(), kTagLensAperture,
                          aperture[0]);
    metadata_logger_->Log(result->frame_number(), kTagAeExposureCompensation,
                          ae_compensation[0]);
  }

  // Face info.
  if (!frame_info->faces) {
    base::span<const int32_t> face_rectangles =
        result->GetMetadata<int32_t>(ANDROID_STATISTICS_FACE_RECTANGLES);
    std::vector<NormalizedRect> faces;
    if (face_rectangles.size() >= 4) {
      for (size_t i = 0; i < face_rectangles.size(); i += 4) {
        const int* rect_bound = &face_rectangles[i];
        faces.push_back(NormalizedRect{
            .x0 = std::clamp(base::checked_cast<float>(rect_bound[0]) /
                                 active_array_dimension_.width,
                             0.0f, 1.0f),
            .x1 = std::clamp(base::checked_cast<float>(rect_bound[2]) /
                                 active_array_dimension_.width,
                             0.0f, 1.0f),
            .y0 = std::clamp(base::checked_cast<float>(rect_bound[1]) /
                                 active_array_dimension_.height,
                             0.0f, 1.0f),
            .y1 = std::clamp(base::checked_cast<float>(rect_bound[3]) /
                                 active_array_dimension_.height,
                             0.0f, 1.0f)});
      }
    }
    frame_info->faces =
        std::make_optional<std::vector<NormalizedRect>>(std::move(faces));
  }
  if (metadata_logger_) {
    const int num_faces = frame_info->faces.value().size();
    std::vector<float> flattened_faces(num_faces * 4);
    for (int i = 0; i < num_faces; ++i) {
      const NormalizedRect& f = frame_info->faces.value()[i];
      const int base = i * 4;
      flattened_faces[base] = f.x0;
      flattened_faces[base + 1] = f.y0;
      flattened_faces[base + 2] = f.x1;
      flattened_faces[base + 3] = f.y1;
    }
    metadata_logger_->Log(result->frame_number(), kTagFaceRectangles,
                          base::span<const float>(flattened_faces.data(),
                                                  flattened_faces.size()));
  }

  // AWB info.
  base::span<const float> color_correction_gains =
      result->GetMetadata<float>(ANDROID_COLOR_CORRECTION_GAINS);
  if (!color_correction_gains.empty()) {
    CHECK_EQ(color_correction_gains.size(), 4);
    memcpy(frame_info->rggb_gains, color_correction_gains.data(),
           4 * sizeof(float));
    VLOGFID(2, result->frame_number())
        << "AWB gains: " << frame_info->rggb_gains[0] << ", "
        << frame_info->rggb_gains[1] << ", " << frame_info->rggb_gains[2]
        << ", " << frame_info->rggb_gains[3];
  } else {
    LOGF(WARNING) << "Cannot get ANDROID_COLOR_CORRECTION_GAINS";
  }

  if (metadata_logger_) {
    metadata_logger_->Log(result->frame_number(), kTagAwbGains,
                          color_correction_gains);
  }

  // CCM
  base::span<const camera_metadata_rational_t> color_correction_transform =
      result->GetMetadata<camera_metadata_rational_t>(
          ANDROID_COLOR_CORRECTION_TRANSFORM);
  if (!color_correction_transform.empty()) {
    CHECK_EQ(color_correction_transform.size(), 9);
    for (int i = 0; i < 9; ++i) {
      frame_info->ccm[i] =
          static_cast<float>(color_correction_transform[i].numerator) /
          static_cast<float>(color_correction_transform[i].denominator);
    }
    VLOGFID(2, result->frame_number())
        << "CCM: " << frame_info->ccm[0] << ", " << frame_info->ccm[1] << ", "
        << frame_info->ccm[2] << ", " << frame_info->ccm[3] << ", "
        << frame_info->ccm[4] << ", " << frame_info->ccm[5] << ", "
        << frame_info->ccm[6] << ", " << frame_info->ccm[7] << ", "
        << frame_info->ccm[8];

  } else {
    LOGF(WARNING) << "Cannot get ANDROID_COLOR_CORRECTION_TRANSFORM";
  }

  if (metadata_logger_) {
    metadata_logger_->Log(result->frame_number(), kTagCcm,
                          color_correction_transform);
  }

  // AE stats.
  ae_device_adapter_->ExtractAeStats(result, metadata_logger_);

  MaybeRunAE(result->frame_number());
}

void GcamAeControllerImpl::OnOptionsUpdated(
    const base::Value::Dict& json_values,
    std::optional<MetadataLogger*> metadata_logger) {
  bool enabled;
  if (LoadIfExist(json_values, kGcamAeEnableKey, &enabled)) {
    if (options_.enabled && !enabled) {
      ae_state_machine_.OnReset();
    }
    options_.enabled = enabled;
  }

  int ae_frame_interval;
  if (LoadIfExist(json_values, kAeFrameIntervalKey, &ae_frame_interval)) {
    if (ae_frame_interval > 0) {
      options_.ae_frame_interval = ae_frame_interval;
    } else {
      LOGF(ERROR) << "Invalid AE frame interval: " << ae_frame_interval;
    }
  }

  auto max_hdr_ratio = json_values.FindDict(kMaxHdrRatioKey);
  if (max_hdr_ratio) {
    base::flat_map<float, float> hdr_ratio_map;
    for (auto [k, v] : *max_hdr_ratio) {
      double gain;
      if (!base::StringToDouble(k, &gain)) {
        LOGF(ERROR) << "Invalid gain value: " << k;
        continue;
      }
      std::optional<double> ratio = v.GetIfDouble();
      if (!ratio) {
        LOGF(ERROR) << "Invalid max_hdr_ratio";
        continue;
      }
      hdr_ratio_map.insert({gain, *ratio});
    }
    options_.max_hdr_ratio = std::move(hdr_ratio_map);
  }

  int ae_stats_input_mode;
  if (LoadIfExist(json_values, kAeStatsInputModeKey, &ae_stats_input_mode)) {
    if (ae_stats_input_mode ==
            static_cast<int>(AeStatsInputMode::kFromVendorAeStats) ||
        ae_stats_input_mode ==
            static_cast<int>(AeStatsInputMode::kFromYuvImage)) {
      options_.ae_stats_input_mode =
          static_cast<AeStatsInputMode>(ae_stats_input_mode);
    } else {
      LOGF(ERROR) << "Invalid AE stats input mode: " << ae_stats_input_mode;
    }
  }

  int ae_override_mode;
  if (LoadIfExist(json_values, kAeOverrideModeKey, &ae_override_mode)) {
    if (ae_override_mode ==
            static_cast<int>(AeOverrideMode::kWithManualSensorControl) ||
        ae_override_mode == static_cast<int>(AeOverrideMode::kWithVendorTag)) {
      options_.ae_override_mode = static_cast<AeOverrideMode>(ae_override_mode);
    } else {
      LOGF(ERROR) << "Invalid AE override method: " << ae_override_mode;
    }
  }

  LoadIfExist(json_values, kExposureCompensationKey,
              &options_.exposure_compensation);

  LoadIfExist(json_values, kGainMultiplier, &options_.gain_multiplier);
  // We need to recompute the sensitivity range when the multiplier changes.
  max_analog_gain_ = options_.gain_multiplier *
                     (static_cast<float>(max_analog_sensitivity_) /
                      static_cast<float>(sensitivity_range_.lower()));
  max_total_gain_ = options_.gain_multiplier *
                    (static_cast<float>(sensitivity_range_.upper()) /
                     static_cast<float>(sensitivity_range_.lower()));

  if (metadata_logger) {
    metadata_logger_ = *metadata_logger;
  }

  if (VLOG_IS_ON(1)) {
    VLOGF(1) << "GcamAeController config:"
             << " enabled=" << options_.enabled
             << " ae_frame_interval=" << options_.ae_frame_interval
             << " ae_stats_input_mode="
             << static_cast<int>(options_.ae_stats_input_mode)
             << " exposure_compensation=" << options_.exposure_compensation
             << " gain_multiplier=" << options_.gain_multiplier
             << " max_analog_gain=" << max_analog_gain_
             << " max_total_gain=" << max_total_gain_
             << " log_frame_metadata=" << !!metadata_logger_;
    VLOGF(1) << "max_hdr_ratio:";
    for (auto [gain, ratio] : options_.max_hdr_ratio) {
      VLOGF(1) << "  " << gain << ": " << ratio;
    }
  }

  ae_state_machine_.OnOptionsUpdated(json_values);
}

std::optional<float> GcamAeControllerImpl::GetCalculatedHdrRatio(
    int frame_number) {
  if (!options_.enabled) {
    return std::nullopt;
  }
  AeFrameInfo* frame_info = GetAeFrameInfoEntry(frame_number);
  if (!frame_info) {
    return std::nullopt;
  }
  if (IsClientManualSensorControlSet(*frame_info)) {
    // The client is doing manual exposure control, so let's not do too much
    // with HDRnet rendering.
    return 1.0f;
  }

  return frame_info->target_hdr_ratio;
}

void GcamAeControllerImpl::SetRequestAeParameters(
    Camera3CaptureDescriptor* request) {
  if (!options_.enabled) {
    return;
  }

  // Set the AE parameters that will be used to actually capture the frame.
  AeFrameInfo* frame_info = CreateAeFrameInfoEntry(request->frame_number());

  RecordClientRequestSettings(request);

  if (IsClientManualSensorControlSet(*frame_info)) {
    return;
  }

  frame_info->target_tet = ae_state_machine_.GetCaptureTet();
  frame_info->target_hdr_ratio = ae_state_machine_.GetFilteredHdrRatio();
  VLOGFID(1, request->frame_number())
      << "Request tet=" << frame_info->target_tet
      << " hdr_ratio=" << frame_info->target_hdr_ratio;
  if (metadata_logger_) {
    metadata_logger_->Log(request->frame_number(), kTagHdrRatio,
                          frame_info->target_hdr_ratio);
  }

  frame_info->base_ae_compensation_log2 = options_.exposure_compensation;
  if (frame_info->client_request_settings.ae_exposure_compensation) {
    frame_info->client_ae_compensation_log2 =
        static_cast<float>(frame_info->client_request_settings
                               .ae_exposure_compensation.value()) *
        ae_compensation_step_;
  }

  base::span<const int32_t> fps_range =
      request->GetMetadata<int32_t>(ANDROID_CONTROL_AE_TARGET_FPS_RANGE);
  if (!fps_range.empty()) {
    frame_info->target_fps_range = {fps_range[0], fps_range[1]};
  }

#if USE_CAMERA_FEATURE_FACE_DETECTION
  // If the FaceDetectionStreamManipulator has set the face ROIs, use them for
  // Gcam AE instead of the ones from the vendor camera HAL.
  if (request->feature_metadata().faces) {
    frame_info->faces = CrosFaceToNormalizedRect(
        *request->feature_metadata().faces, active_array_dimension_);
  }
#endif

  // Only change the metadata when the client request settings is not null.
  // This is mainly to make the CTS tests happy, as some test cases set null
  // settings and if we change that the vendor camera HAL may not handle the
  // incremental changes well.
  if (!request->has_metadata()) {
    return;
  }

  if (!ae_device_adapter_->WriteRequestParameters(request)) {
    LOGFID(ERROR, request->frame_number()) << "Cannot set request parameters";
    return;
  }

  switch (options_.ae_override_mode) {
    case AeOverrideMode::kWithManualSensorControl:
      SetManualSensorControls(request);
      break;
    case AeOverrideMode::kWithVendorTag:
      if (!ae_device_adapter_->SetExposureTargetVendorTag(
              request, frame_info->target_tet)) {
        DVLOGFID(2, request->frame_number())
            << "Failed to override AE with vendor tag";
      }
      break;
    default:
      NOTREACHED() << "Invalid AeOverrideMethod";
  }
}

void GcamAeControllerImpl::SetResultAeMetadata(
    Camera3CaptureDescriptor* result) {
  if (!options_.enabled) {
    return;
  }

  AeFrameInfo* frame_info = GetAeFrameInfoEntry(result->frame_number());
  if (!frame_info || IsClientManualSensorControlSet(*frame_info)) {
    return;
  }

  if (options_.ae_override_mode == AeOverrideMode::kWithManualSensorControl ||
      options_.ae_override_mode == AeOverrideMode::kWithVendorTag) {
    std::array<uint8_t, 1> ae_state = {ae_state_machine_.GetAndroidAeState()};
    if (!result->UpdateMetadata<uint8_t>(ANDROID_CONTROL_AE_STATE, ae_state)) {
      LOGF(ERROR) << "Cannot set ANDROID_CONTROL_AE_STATE";
    }
  }

  RestoreClientRequestSettings(result);
}

void GcamAeControllerImpl::MaybeRunAE(int frame_number) {
  AeFrameInfo* frame_info = GetAeFrameInfoEntry(frame_number);
  DCHECK(frame_info);
  if (!ShouldRunAe(frame_number) || !frame_info->IsValid() ||
      !ae_device_adapter_->HasAeStats(frame_number)) {
    return;
  }

  TRACE_GCAM_AE_BEGIN(kEventRun, "frame_number", frame_number);
  float max_hdr_ratio =
      LookUpHdrRatio(options_.max_hdr_ratio,
                     frame_info->analog_gain * frame_info->digital_gain);
  // From 0.1 ms with 1x gain to maximum possible exposure time with maximum
  // analog plus digital gain.
  Range<float> default_device_tet_range = {
      0.1, static_cast<float>((1000.0 / frame_info->target_fps_range.lower()) *
                              max_total_gain_)};
  AeParameters ae_parameters = ae_device_adapter_->ComputeAeParameters(
      frame_number, *frame_info, default_device_tet_range, max_hdr_ratio);
  VLOGFID(1, frame_info->frame_number)
      << "total gain=" << frame_info->analog_gain * frame_info->digital_gain
      << " max_hdr_ratio=" << max_hdr_ratio
      << " tet_range=" << ae_parameters.tet_range;

  ae_state_machine_.OnNewAeParameters({.ae_frame_info = *frame_info,
                                       .ae_parameters = ae_parameters,
                                       .tet_range = ae_parameters.tet_range},
                                      metadata_logger_);
  TRACE_GCAM_AE_END();

  if (metadata_logger_) {
    metadata_logger_->Log(
        frame_info->frame_number, kTagFrameWidth,
        base::checked_cast<int32_t>(active_array_dimension_.width));
    metadata_logger_->Log(
        frame_info->frame_number, kTagFrameHeight,
        base::checked_cast<int32_t>(active_array_dimension_.height));
    metadata_logger_->Log(frame_number, kTagMaxHdrRatio, max_hdr_ratio);
  }
}

void GcamAeControllerImpl::RecordClientRequestSettings(
    const Camera3CaptureDescriptor* request) {
  AeFrameInfo* frame_info = GetAeFrameInfoEntry(request->frame_number());
  DCHECK(frame_info);

  base::span<const uint8_t> ae_mode =
      request->GetMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE);
  if (!ae_mode.empty()) {
    frame_info->client_request_settings.ae_mode = ae_mode[0];
    VLOGFID(2, request->frame_number())
        << "Client requested ANDROID_CONTROL_AE_MODE="
        << static_cast<int>(*frame_info->client_request_settings.ae_mode);
  }

  base::span<const int32_t> ae_comp =
      request->GetMetadata<int32_t>(ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION);
  if (!ae_comp.empty()) {
    frame_info->client_request_settings.ae_exposure_compensation = ae_comp[0];
    VLOGFID(2, request->frame_number())
        << "Client requested ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION="
        << static_cast<int>(
               *frame_info->client_request_settings.ae_exposure_compensation);
  }

  base::span<const uint8_t> ae_lock =
      request->GetMetadata<uint8_t>(ANDROID_CONTROL_AE_LOCK);
  if (!ae_lock.empty()) {
    frame_info->client_request_settings.ae_lock = ae_lock[0];
    VLOGFID(2, request->frame_number())
        << "Client requested ANDROID_CONTROL_AE_LOCK="
        << static_cast<int>(*frame_info->client_request_settings.ae_lock);
  }

  base::span<const uint8_t> ae_antibanding_mode =
      request->GetMetadata<uint8_t>(ANDROID_CONTROL_AE_ANTIBANDING_MODE);
  if (!ae_antibanding_mode.empty()) {
    frame_info->client_request_settings.ae_antibanding_mode =
        ae_antibanding_mode[0];
    VLOGFID(2, request->frame_number())
        << "Client requested ANDROID_CONTROL_AE_ANTIBANDING_MODE="
        << static_cast<int>(
               *frame_info->client_request_settings.ae_antibanding_mode);
  }
}

void GcamAeControllerImpl::RestoreClientRequestSettings(
    Camera3CaptureDescriptor* result) {
  AeFrameInfo* frame_info = GetAeFrameInfoEntry(result->frame_number());
  DCHECK(frame_info);

  if (frame_info->client_request_settings.ae_mode) {
    std::array<uint8_t, 1> ae_mode = {
        *frame_info->client_request_settings.ae_mode};
    if (!result->UpdateMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE, ae_mode)) {
      LOGF(ERROR) << "Cannot restore ANDROID_CONTROL_AE_MODE";
    } else {
      VLOGFID(2, result->frame_number())
          << "Restored ANDROID_CONTROL_AE_MODE="
          << static_cast<int>(*frame_info->client_request_settings.ae_mode);
    }
  }

  if (frame_info->client_request_settings.ae_exposure_compensation) {
    std::array<int32_t, 1> ae_exposure_compensation = {
        *frame_info->client_request_settings.ae_exposure_compensation};
    if (!result->UpdateMetadata<int32_t>(
            ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
            ae_exposure_compensation)) {
      LOGF(ERROR) << "Cannot restore ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION";
    } else {
      VLOGFID(2, result->frame_number())
          << "Restored ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION="
          << static_cast<int>(
                 *frame_info->client_request_settings.ae_exposure_compensation);
    }
  }

  if (frame_info->client_request_settings.ae_lock) {
    std::array<uint8_t, 1> ae_lock = {
        *frame_info->client_request_settings.ae_lock};
    if (!result->UpdateMetadata<uint8_t>(ANDROID_CONTROL_AE_LOCK, ae_lock)) {
      LOGF(ERROR) << "Cannot restore ANDROID_CONTROL_AE_LOCK";
    } else {
      VLOGFID(2, result->frame_number())
          << "Restored ANDROID_CONTROL_AE_LOCK="
          << static_cast<int>(*frame_info->client_request_settings.ae_lock);
    }
  }

  if (frame_info->client_request_settings.ae_antibanding_mode) {
    std::array<uint8_t, 1> ae_antibanding_mode = {
        *frame_info->client_request_settings.ae_antibanding_mode};
    if (!result->UpdateMetadata<uint8_t>(ANDROID_CONTROL_AE_ANTIBANDING_MODE,
                                         ae_antibanding_mode)) {
      LOGF(ERROR) << "Cannot restore ANDROID_CONTROL_AE_ANTIBANDING_MODE";
    } else {
      VLOGFID(2, result->frame_number())
          << "Restored ANDROID_CONTROL_AE_ANTIBANDING_MODE="
          << static_cast<int>(
                 *frame_info->client_request_settings.ae_antibanding_mode);
    }
  }
}

void GcamAeControllerImpl::SetManualSensorControls(
    Camera3CaptureDescriptor* request) {
  constexpr float kSecondInMs = 1000.0f;
  auto get_exposure_time_rounding_for_antibanding =
      [&](uint8_t antibanding_mode) -> float {
    constexpr float kExpTimeMs50HzRounding = (kSecondInMs / 50.0) / 2.0;
    constexpr float kExpTimeMs60HzRounding = (kSecondInMs / 60.0) / 2.0;
    constexpr float kExpTimeMsNoRounding = 0.001f;
    switch (antibanding_mode) {
      case ANDROID_CONTROL_AE_ANTIBANDING_MODE_50HZ:
        return kExpTimeMs50HzRounding;
      case ANDROID_CONTROL_AE_ANTIBANDING_MODE_60HZ:
        return kExpTimeMs60HzRounding;
      case ANDROID_CONTROL_AE_ANTIBANDING_MODE_AUTO:
        switch (powerline_freq_) {
          case V4L2_CID_POWER_LINE_FREQUENCY_50HZ:
            return kExpTimeMs50HzRounding;
          case V4L2_CID_POWER_LINE_FREQUENCY_60HZ:
            return kExpTimeMs60HzRounding;
          default:
            NOTREACHED() << "Powerline frequency not set";
            return kExpTimeMsNoRounding;
        }
        break;
      case ANDROID_CONTROL_AE_ANTIBANDING_MODE_OFF:
        return kExpTimeMsNoRounding;
      default:
        NOTREACHED() << "Unknown antibanding_mode enum: "
                     << static_cast<int>(antibanding_mode);
        return kExpTimeMsNoRounding;
    }
  };

  auto factorize_exp_time_and_gain =
      [&](const float tet, const float max_exposure_time_ms,
          const float exp_time_rounding_ms) -> std::tuple<float, float> {
    float exp_time = tet;
    if (tet > exp_time_rounding_ms) {
      exp_time = std::max(std::floorf(std::min(tet, max_exposure_time_ms) /
                                      exp_time_rounding_ms),
                          1.0f) *
                 exp_time_rounding_ms;
    }
    float gain = tet / exp_time;
    return std::make_tuple(exp_time, gain);
  };

  AeFrameInfo* frame_info = GetAeFrameInfoEntry(request->frame_number());
  if (!frame_info->target_tet) {
    return;
  }

  // Defaults to 30fps.
  float max_exposure_time_ms = 33.3f;
  if (frame_info->target_fps_range.lower() == 0) {
    LOGFID(ERROR, frame_info->frame_number)
        << "Invalid fps range: " << frame_info->target_fps_range;
  } else {
    max_exposure_time_ms =
        kSecondInMs /
        base::checked_cast<float>(frame_info->target_fps_range.lower());
  }
  uint8_t ae_antibanding_mode =
      frame_info->client_request_settings.ae_antibanding_mode
          ? *frame_info->client_request_settings.ae_antibanding_mode
          : ANDROID_CONTROL_AE_ANTIBANDING_MODE_AUTO;

  auto [exp_time, gain] = factorize_exp_time_and_gain(
      frame_info->target_tet, max_exposure_time_ms,
      get_exposure_time_rounding_for_antibanding(ae_antibanding_mode));
  VLOGFID(2, request->frame_number())
      << "exp_time=" << exp_time << " gain=" << gain
      << " antibanding_mode=" << static_cast<int>(ae_antibanding_mode);

  std::array<uint8_t, 1> ae_mode = {ANDROID_CONTROL_AE_MODE_OFF};
  std::array<uint8_t, 1> ae_lock = {ANDROID_CONTROL_AE_LOCK_OFF};
  std::array<int64_t, 1> exposure_time = {
      base::checked_cast<int64_t>(exp_time * 1e6)};
  std::array<int32_t, 1> sensitivity = {sensitivity_range_.Clamp(
      base::checked_cast<int32_t>(sensitivity_range_.lower() * gain))};
  if (!request->UpdateMetadata<uint8_t>(ANDROID_CONTROL_AE_MODE, ae_mode) ||
      !request->UpdateMetadata<uint8_t>(ANDROID_CONTROL_AE_LOCK, ae_lock) ||
      !request->UpdateMetadata<int64_t>(ANDROID_SENSOR_EXPOSURE_TIME,
                                        exposure_time) ||
      !request->UpdateMetadata<int32_t>(ANDROID_SENSOR_SENSITIVITY,
                                        sensitivity)) {
    LOGF(ERROR) << "Cannot set manual sensor control parameters";
    return;
  }

  if (metadata_logger_) {
    metadata_logger_->Log(request->frame_number(), kTagRequestExpTime,
                          exposure_time[0]);
    metadata_logger_->Log(request->frame_number(), kTagRequestSensitivity,
                          sensitivity[0]);
  }
}

bool GcamAeControllerImpl::ShouldRunAe(int frame_number) const {
  return options_.enabled && (frame_number % options_.ae_frame_interval == 0);
}

AeFrameInfo* GcamAeControllerImpl::CreateAeFrameInfoEntry(int frame_number) {
  int index = frame_number % frame_info_.size();
  AeFrameInfo& entry = frame_info_[index];
  if (entry.frame_number != frame_number) {
    // Clear the data of the outdated frame.
    entry = AeFrameInfo({.frame_number = frame_number,
                         .ae_stats_input_mode = options_.ae_stats_input_mode,
                         .active_array_dimension = active_array_dimension_});
  }
  return &entry;
}

AeFrameInfo* GcamAeControllerImpl::GetAeFrameInfoEntry(int frame_number) {
  int index = frame_number % frame_info_.size();
  if (frame_info_[index].frame_number != frame_number) {
    return nullptr;
  }
  return &frame_info_[index];
}

}  // namespace cros
