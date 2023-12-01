/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef CAMERA_INCLUDE_CROS_CAMERA_CONSTANTS_H_
#define CAMERA_INCLUDE_CROS_CAMERA_CONSTANTS_H_

namespace cros {

namespace constants {

const char kArcCameraGroup[] = "arc-camera";
const char kCrosCameraAlgoSocketPathString[] = "/run/camera/camera-algo.sock";
const char kCrosCameraGPUAlgoSocketPathString[] =
    "/run/camera/camera-gpu-algo.sock";
const char kCrosCameraSocketPathString[] = "/run/camera/camera3.sock";
const char kCrosCameraTestConfigPathString[] =
    "/var/cache/camera/test_config.json";
const char kCrosCameraConfigPathString[] = "/run/camera/camera_config.json";

// Special file to force start cros-camera service regardless of individual
// camera HAL initialization failures.
const char kForceStartCrosCameraPath[] = "/run/camera/force_start_cros_camera";

// Special files to force control face ae.
const char kForceEnableFaceAePath[] = "/run/camera/force_enable_face_ae";
const char kForceDisableFaceAePath[] = "/run/camera/force_disable_face_ae";

const char kForceEnableHdrNetPath[] = "/run/camera/force_enable_hdrnet";
const char kForceDisableHdrNetPath[] = "/run/camera/force_disable_hdrnet";

const char kForceEnableAutoFramingPath[] =
    "/run/camera/force_enable_auto_framing";
const char kForceDisableAutoFramingPath[] =
    "/run/camera/force_disable_auto_framing";

// Special files to force control effects
const char kForceEnableEffectsPath[] = "/run/camera/force_enable_effects";
const char kForceDisableEffectsPath[] = "/run/camera/force_disable_effects";

// ------Configuration for |kCrosCameraTestConfigPathString|-------
// boolean value used in test mode for forcing hardware jpeg encode/decode in
// USB HAL (won't fallback to SW encode/decode).
const char kCrosForceJpegHardwareEncodeOption[] = "force_jpeg_hw_enc";
const char kCrosForceJpegHardwareDecodeOption[] = "force_jpeg_hw_dec";

// boolean value for specify enable/disable camera of target facing in camera
// service.
const char kCrosEnableFrontCameraOption[] = "enable_front_camera";
const char kCrosEnableBackCameraOption[] = "enable_back_camera";
const char kCrosEnableExternalCameraOption[] = "enable_external_camera";

// List of string of enabled camera HAL. The format is a list of the HAL .so
// file names. e.g. ["usb.so", "fake.so"].
const char kCrosEnabledHalsOption[] = "enabled_hals";

// boolean value for specify enable/disable the mechanism to abort camera
// service when capture request/response monitors reach timeout.
const char kCrosAbortWhenCaptureMonitorTimeout[] =
    "abort_when_capture_monitor_timeout";
// ------End configuration for |kCrosCameraTestConfigPathString|-------

// ------Configuration for |kCrosCameraConfigPathString|-------
const char kCrosUsbMaxStreamWidth[] = "usb_max_stream_width";
const char kCrosUsbMaxStreamHeight[] = "usb_max_stream_height";
const char kCrosUsbAndroidMaxStreamWidth[] = "usb_android_max_stream_width";
const char kCrosUsbAndroidMaxStreamHeight[] = "usb_android_max_stream_height";
// Use JDA for resolution <= (kCrosUsbJDAMaxWidth, kCrosUsbJDAMaxHeight)
const char kCrosUsbJDACapWidth[] = "usb_jda_cap_width";
const char kCrosUsbJDACapHeight[] = "usb_jda_cap_height";
// Filtered out resolutions. The format is a list string of resolutions. e.g.
// ["w1xh1", "w2xh2"]
const char kCrosUsbFilteredOutResolutions[] = "usb_filtered_out_resolutions";
// The lookback time for zero-shutter lag (ZSL) in nanoseconds.
const char kCrosZslLookback[] = "zsl_lookback";
// ------End configuration for |kCrosCameraConfigPathString|-------

}  // namespace constants
}  // namespace cros
#endif  // CAMERA_INCLUDE_CROS_CAMERA_CONSTANTS_H_
