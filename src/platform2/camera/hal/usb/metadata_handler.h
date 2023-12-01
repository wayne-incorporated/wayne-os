/* Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_HAL_USB_METADATA_HANDLER_H_
#define CAMERA_HAL_USB_METADATA_HANDLER_H_

#include <map>
#include <memory>
#include <vector>

#include <base/threading/thread_checker.h>
#include <camera/camera_metadata.h>
#include <hardware/camera3.h>

#include "cros-camera/common_types.h"
#include "cros-camera/face_detector_client_cros_wrapper.h"
#include "hal/usb/common_types.h"
#include "hal/usb/v4l2_camera_device.h"

namespace cros {

using AwbModeToTemperatureMap =
    std::map<camera_metadata_enum_android_control_awb_mode, uint32_t>;

struct CameraMetadataDeleter {
  inline void operator()(camera_metadata_t* metadata) const {
    free_camera_metadata(metadata);
  }
};

typedef std::unique_ptr<camera_metadata_t, CameraMetadataDeleter>
    ScopedCameraMetadata;

// MetadataHandler is thread-safe. It is used for saving metadata states of
// CameraDevice.
class MetadataHandler {
 public:
  MetadataHandler(const camera_metadata_t& static_metadata,
                  const camera_metadata_t& request_template,
                  const DeviceInfo& device_info,
                  V4L2CameraDevice* device,
                  const SupportedFormats& supported_formats);
  ~MetadataHandler();

  static int FillDefaultMetadata(android::CameraMetadata* static_metadata,
                                 android::CameraMetadata* request_metadata);

  static int FillMetadataFromSupportedFormats(
      const SupportedFormats& supported_formats,
      const DeviceInfo& device_info,
      android::CameraMetadata* static_metadata,
      android::CameraMetadata* request_metadata);

  static int FillMetadataFromDeviceInfo(
      const DeviceInfo& device_info,
      android::CameraMetadata* static_metadata,
      android::CameraMetadata* request_metadata);

  static int FillSensorInfo(const DeviceInfo& device_info,
                            android::CameraMetadata* metadata,
                            int32_t array_width,
                            int32_t array_height);

  // Get default settings according to the |template_type|. Can be called on
  // any thread.
  const camera_metadata_t* GetDefaultRequestSettings(int template_type);

  // PreHandleRequest and PostHandleRequest should run on the same thread.

  // Called before the request is processed. This function is used for checking
  // metadata values to setup related states and image settings.
  int PreHandleRequest(int frame_number,
                       const Size& resolution,
                       android::CameraMetadata* metadata);

  // Called after the request is processed. This function is used to update
  // required metadata which can be gotton from 3A or image processor.
  int PostHandleRequest(int frame_number,
                        int64_t timestamp,
                        const Size& resolution,
                        const std::vector<human_sensing::CrosFace>& faces,
                        android::CameraMetadata* metadata);

 private:
  // Check |template_type| is valid or not.
  bool IsValidTemplateType(int template_type);

  // Check if constant frame rate should be enabled or not.
  bool ShouldEnableConstantFrameRate(
      const android::CameraMetadata* metadata) const;

  // Return a copy of metadata according to |template_type|.
  ScopedCameraMetadata CreateDefaultRequestSettings(int template_type);
  int FillDefaultPreviewSettings(android::CameraMetadata* metadata);
  int FillDefaultStillCaptureSettings(android::CameraMetadata* metadata);
  int FillDefaultVideoRecordSettings(android::CameraMetadata* metadata);
  int FillDefaultVideoSnapshotSettings(android::CameraMetadata* metadata);
  int FillDefaultZeroShutterLagSettings(android::CameraMetadata* metadata);
  int FillDefaultManualSettings(android::CameraMetadata* metadata);

  static AwbModeToTemperatureMap GetAvailableAwbTemperatures(
      const DeviceInfo& device_info);

  // Metadata containing persistent camera characteristics.
  android::CameraMetadata static_metadata_;
  // The base template for constructing request settings.
  android::CameraMetadata request_template_;

  // Static array of standard camera settings templates. These are owned by
  // CameraClient.
  ScopedCameraMetadata template_settings_[CAMERA3_TEMPLATE_COUNT];

  // Use to check PreHandleRequest and PostHandleRequest are called on the same
  // thread.
  base::ThreadChecker thread_checker_;

  // Camera device information.
  const DeviceInfo device_info_;

  // Delegate to communicate with camera device. Caller owns the ownership.
  V4L2CameraDevice* device_;

  int current_frame_number_;

  bool af_trigger_;

  int max_supported_fps_;

  // Awb mode to color temperature map
  AwbModeToTemperatureMap awb_temperature_;
  bool is_awb_control_supported_;

  bool is_brightness_control_supported_;
  bool is_contrast_control_supported_;
  bool is_pan_control_supported_;
  bool is_saturation_control_supported_;
  bool is_sharpness_control_supported_;
  bool is_tilt_control_supported_;
  bool is_zoom_control_supported_;

  uint32_t focus_distance_normalize_factor_;
  ControlRange focus_distance_range_;
};

}  // namespace cros

#endif  // CAMERA_HAL_USB_METADATA_HANDLER_H_
