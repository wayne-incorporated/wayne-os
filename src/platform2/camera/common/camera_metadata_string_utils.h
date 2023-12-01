/*
 * Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_COMMON_CAMERA_METADATA_STRING_UTILS_H_
#define CAMERA_COMMON_CAMERA_METADATA_STRING_UTILS_H_

#include <string>

#include <base/containers/queue.h>
#include <base/time/time.h>
#include <system/camera_metadata.h>

#include "cros-camera/export.h"

namespace cros {

// Helper functions to convert camera metadata to string

CROS_CAMERA_EXPORT std::string TimestampsToFPSString(
    const base::queue<base::TimeTicks>& timestamps);

CROS_CAMERA_EXPORT std::string FaceInfoToString(
    camera_metadata_enum_android_statistics_face_detect_mode_t face_detect_mode,
    size_t num_faces);

CROS_CAMERA_EXPORT std::string FocusDistanceToString(double focus_distance);

CROS_CAMERA_EXPORT const char* AFStateToString(
    camera_metadata_enum_android_control_af_state_t state);

CROS_CAMERA_EXPORT const char* AEModeToString(
    camera_metadata_enum_android_control_ae_antibanding_mode_t mode);

CROS_CAMERA_EXPORT const char* AEStateToString(
    camera_metadata_enum_android_control_ae_state_t state);

CROS_CAMERA_EXPORT std::string SensitivityToString(
    int32_t sensor_sensitivity, int32_t sensor_sensitivity_boost);

CROS_CAMERA_EXPORT std::string FrameDurationToString(int64_t frame_duration);

CROS_CAMERA_EXPORT std::string ExposureTimeToString(int64_t exposure_time);

CROS_CAMERA_EXPORT std::string ColorGainToString(double gain);

CROS_CAMERA_EXPORT const char* AWBStateToString(
    camera_metadata_enum_android_control_awb_state_t state);

CROS_CAMERA_EXPORT std::string HdrRatioToString(float hdr_ratio);

}  // namespace cros

#endif  // CAMERA_COMMON_CAMERA_METADATA_STRING_UTILS_H_
