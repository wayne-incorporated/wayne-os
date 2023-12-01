/* Copyright 2019 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <vector>

#include "hal/ip/metadata_handler.h"
#include "hal/usb/vendor_tag.h"

namespace cros {

MetadataHandler::MetadataHandler() {}

MetadataHandler::~MetadataHandler() {}

android::CameraMetadata MetadataHandler::CreateStaticMetadata(
    const std::string& ip,
    const std::string& name,
    int format,
    double fps,
    const std::vector<mojom::IpCameraStreamPtr>& streams) {
  android::CameraMetadata metadata;

  std::vector<int32_t> characteristic_keys = {
      ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES,
      ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS,
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
      ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE,
      ANDROID_SENSOR_ORIENTATION,
      ANDROID_REQUEST_PIPELINE_MAX_DEPTH,
  };

  metadata.update(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS,
                  characteristic_keys);

  std::vector<int32_t> request_keys = {};
  metadata.update(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS, request_keys);

  std::vector<int32_t> result_keys = {
      ANDROID_LENS_STATE,
  };
  metadata.update(ANDROID_REQUEST_AVAILABLE_RESULT_KEYS, result_keys);

  std::vector<int32_t> available_fps_ranges;
  available_fps_ranges.push_back(fps);
  available_fps_ranges.push_back(fps);
  metadata.update(ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES,
                  available_fps_ranges);

  std::vector<int64_t> min_frame_durations;
  std::vector<int32_t> stream_configurations;
  int32_t max_width = 0;
  int32_t max_height = 0;

  for (const auto& stream : streams) {
    int32_t width = stream->width;
    int32_t height = stream->height;

    if (width > max_width) {
      max_width = width;
      max_height = height;
    }

    min_frame_durations.push_back(format);
    min_frame_durations.push_back(width);
    min_frame_durations.push_back(height);
    min_frame_durations.push_back(static_cast<int64_t>(1e9 / fps));

    stream_configurations.push_back(format);
    stream_configurations.push_back(width);
    stream_configurations.push_back(height);
    stream_configurations.push_back(
        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT);
  }

  metadata.update(ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS,
                  min_frame_durations);
  metadata.update(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
                  stream_configurations);

  std::vector<int32_t> active_array_size = {0, 0, max_width, max_height};
  metadata.update(ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE, active_array_size);

  int32_t sensor_orientation = 0;
  metadata.update(ANDROID_SENSOR_ORIENTATION, &sensor_orientation, 1);

  const uint8_t request_pipeline_max_depth = 4;
  metadata.update(ANDROID_REQUEST_PIPELINE_MAX_DEPTH,
                  &request_pipeline_max_depth, 1);

  metadata.update(kVendorTagDevicePath, ip);
  metadata.update(kVendorTagModelName, name);

  return metadata;
}

camera_metadata_t* MetadataHandler::GetDefaultRequestSettings() {
  static camera_metadata_t* default_metadata = allocate_camera_metadata(0, 0);
  return default_metadata;
}

void MetadataHandler::AddResultMetadata(android::CameraMetadata* metadata) {
  std::vector<uint8_t> lens_state = {ANDROID_LENS_STATE_STATIONARY};
  metadata->update(ANDROID_LENS_STATE, lens_state);
}

}  // namespace cros
