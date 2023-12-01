/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "common/camera_metadata_string_utils.h"

#include <cinttypes>

#include <base/strings/stringprintf.h>

namespace cros {

namespace {

static constexpr char k50HzStr[] = "50Hz";
static constexpr char k60HzStr[] = "60Hz";
static constexpr char kActiveScanStr[] = "ACTIVE_SCAN";
static constexpr char kAutoStr[] = "AUTO";
static constexpr char kConvergedStr[] = "CONVERGED";
static constexpr char kFlashRequiredStr[] = "FLASH_REQUIRED";
static constexpr char kFocusedLockedStr[] = "FOCUSED_LOCKED";
static constexpr char kInactiveStr[] = "INACTIVE";
static constexpr char kLockedStr[] = "LOCKED";
static constexpr char kNotFocusedLockedStr[] = "NOT_FOCUSED_LOCKED";
static constexpr char kOffStr[] = "OFF";
static constexpr char kPassiveFocusedStr[] = "PASSIVE_FOCUSED";
static constexpr char kPassiveScanStr[] = "PASSIVE_SCAN";
static constexpr char kPassiveUnfocusedStr[] = "PASSIVE_UNFOCUSED";
static constexpr char kPrecaptureStr[] = "PRECAPTURE";
static constexpr char kSearchingStr[] = "SEARCHING";

}  // namespace

std::string TimestampsToFPSString(
    const base::queue<base::TimeTicks>& timestamps) {
  if (timestamps.size() < 2) {
    return "";
  }
  return base::StringPrintf(
      "%.0f FPS", static_cast<double>(timestamps.size()) /
                      (timestamps.back() - timestamps.front()).InSecondsF());
}

std::string FaceInfoToString(
    camera_metadata_enum_android_statistics_face_detect_mode_t face_detect_mode,
    size_t num_faces) {
  if (face_detect_mode == ANDROID_STATISTICS_FACE_DETECT_MODE_OFF) {
    return kOffStr;
  }
  num_faces /= 4;
  return base::StringPrintf("%" PRIu64 " %s", static_cast<uint64_t>(num_faces),
                            num_faces >= 2 ? "Faces" : "Face");
}

std::string FocusDistanceToString(double focus_distance) {
  if (focus_distance == 0) {
    return "";
  }
  return base::StringPrintf("%.1f cm", 100 / focus_distance);
}

const char* AFStateToString(
    camera_metadata_enum_android_control_af_state_t state) {
  switch (state) {
    case ANDROID_CONTROL_AF_STATE_INACTIVE:
      return kInactiveStr;
    case ANDROID_CONTROL_AF_STATE_PASSIVE_SCAN:
      return kPassiveScanStr;
    case ANDROID_CONTROL_AF_STATE_PASSIVE_FOCUSED:
      return kPassiveFocusedStr;
    case ANDROID_CONTROL_AF_STATE_ACTIVE_SCAN:
      return kActiveScanStr;
    case ANDROID_CONTROL_AF_STATE_FOCUSED_LOCKED:
      return kFocusedLockedStr;
    case ANDROID_CONTROL_AF_STATE_NOT_FOCUSED_LOCKED:
      return kNotFocusedLockedStr;
    case ANDROID_CONTROL_AF_STATE_PASSIVE_UNFOCUSED:
      return kPassiveUnfocusedStr;
  }
}

const char* AEModeToString(
    camera_metadata_enum_android_control_ae_antibanding_mode_t mode) {
  switch (mode) {
    case ANDROID_CONTROL_AE_ANTIBANDING_MODE_OFF:
      return kOffStr;
    case ANDROID_CONTROL_AE_ANTIBANDING_MODE_50HZ:
      return k50HzStr;
    case ANDROID_CONTROL_AE_ANTIBANDING_MODE_60HZ:
      return k60HzStr;
    case ANDROID_CONTROL_AE_ANTIBANDING_MODE_AUTO:
      return kAutoStr;
  }
}

const char* AEStateToString(
    camera_metadata_enum_android_control_ae_state_t state) {
  switch (state) {
    case ANDROID_CONTROL_AE_STATE_INACTIVE:
      return kInactiveStr;
    case ANDROID_CONTROL_AE_STATE_SEARCHING:
      return kSearchingStr;
    case ANDROID_CONTROL_AE_STATE_CONVERGED:
      return kConvergedStr;
    case ANDROID_CONTROL_AE_STATE_LOCKED:
      return kLockedStr;
    case ANDROID_CONTROL_AE_STATE_FLASH_REQUIRED:
      return kFlashRequiredStr;
    case ANDROID_CONTROL_AE_STATE_PRECAPTURE:
      return kPrecaptureStr;
  }
}

std::string SensitivityToString(int32_t sensor_sensitivity,
                                int32_t sensor_sensitivity_boost) {
  return base::StringPrintf(
      "ISO %.1f",
      static_cast<double>(sensor_sensitivity * sensor_sensitivity_boost) / 100);
}

std::string FrameDurationToString(int64_t frame_duration) {
  return base::StringPrintf("%.0f Hz",
                            1e9 / static_cast<double>(frame_duration));
}

std::string ExposureTimeToString(int64_t exposure_time) {
  return base::StringPrintf("1/%.0f", 1e9 / static_cast<double>(exposure_time));
}

std::string ColorGainToString(double gain) {
  return base::StringPrintf("%.2fx", gain);
}

const char* AWBStateToString(
    camera_metadata_enum_android_control_awb_state_t state) {
  switch (state) {
    case ANDROID_CONTROL_AWB_STATE_INACTIVE:
      return kInactiveStr;
    case ANDROID_CONTROL_AWB_STATE_SEARCHING:
      return kSearchingStr;
    case ANDROID_CONTROL_AWB_STATE_CONVERGED:
      return kConvergedStr;
    case ANDROID_CONTROL_AWB_STATE_LOCKED:
      return kLockedStr;
  }
}

std::string HdrRatioToString(float hdr_ratio) {
  return base::StringPrintf("%.2f", hdr_ratio);
}

}  // namespace cros
