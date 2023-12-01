/*
 * Copyright 2016 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "hal/usb/metadata_handler.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <base/check.h>
#include <base/containers/fixed_flat_set.h>
#include <base/no_destructor.h>

#include "cros-camera/common.h"
#include "cros-camera/utils/camera_config.h"
#include "hal/usb/quirks.h"
#include "hal/usb/stream_format.h"
#include "hal/usb/v4l2_camera_device.h"
#include "hal/usb/vendor_tag.h"

namespace cros {

namespace {

constexpr int32_t kMinFps = 1;
constexpr float kDefaultAvailableFocalLength = 1.6f;
constexpr float kDefaultMinimumFocusDistance = 0.3f;
constexpr float kDefaultLensFocusDistance = 0.5f;

const cros::AwbModeToTemperatureMap& GetAwbModeTemperatureMap() {
  // https://source.android.com/devices/camera/camera3_3Amodes#auto-wb
  static const base::NoDestructor<cros::AwbModeToTemperatureMap>
      kAwbModeTemperatureMap({
          {ANDROID_CONTROL_AWB_MODE_INCANDESCENT, 2700},
          {ANDROID_CONTROL_AWB_MODE_FLUORESCENT, 5000},
          {ANDROID_CONTROL_AWB_MODE_WARM_FLUORESCENT, 3000},
          {ANDROID_CONTROL_AWB_MODE_DAYLIGHT, 5500},
          {ANDROID_CONTROL_AWB_MODE_CLOUDY_DAYLIGHT, 6500},
          {ANDROID_CONTROL_AWB_MODE_TWILIGHT, 15000},
          {ANDROID_CONTROL_AWB_MODE_SHADE, 7500},
      });
  return *kAwbModeTemperatureMap;
}

uint32_t GetAwbTemperatureByMode(
    const cros::ControlRange& range,
    camera_metadata_enum_android_control_awb_mode mode) {
  const cros::AwbModeToTemperatureMap& map = GetAwbModeTemperatureMap();

  if (mode == ANDROID_CONTROL_AWB_MODE_AUTO)
    return 0;

  auto it = map.find(mode);
  if (it == map.end()) {
    LOGF(ERROR) << "Can't find mode " << mode;
    return 0;
  }

  // Get acceptable temperature by minimum and step. in case the step is
  // too large.
  uint32_t temperature =
      range.minimum + range.step * ((it->second - range.minimum) / range.step);

  if (temperature < range.minimum || temperature > range.maximum)
    return 0;

  return temperature;
}

std::vector<float> GetPhysicalSize(float horiz_fov,
                                   float vert_fov,
                                   float focal_length,
                                   float array_aspect,
                                   float still_aspect) {
  float angle_to_rad_ratio = M_PI / 180.f;
  float crop_factor = still_aspect / array_aspect;
  float horiz_crop_factor = std::min(1.f, crop_factor);
  float vert_crop_factor = std::min(1.f, 1.f / crop_factor);
  return {2.f * focal_length * std::tan(horiz_fov * angle_to_rad_ratio / 2.f) /
              horiz_crop_factor,
          2.f * focal_length * std::tan(vert_fov * angle_to_rad_ratio / 2.f) /
              vert_crop_factor};
}

// The unit of ANDROID_LENS_FOCUS_DISTANCE is diopters (1/meter), but the unit
// of V4L2_CID_FOCUS_ABSOLUTE is undefined. We map the V4L2 value to diopters by
// (value - minimum) / normalize_factor where |value| is in [minimum, maximum].
// We calculate a proper |normalize_factor| by assuming the minimum focus
// distance of USB cameras is >= 1cm (tested on real webcams), i.e. max diopter
// is <= 100, and only use power of 10s for readability.
// For example, V4L2 range [0, 250] will map to Android range [0, 25], where the
// minimum focus distance is 1m/25=4cm. This function takes |v4l2_range|
// (== maximum - minimum) and returns |normalize_factor|.
uint32_t GetNormalizeFactorForV4l2FocusRange(float v4l2_range) {
  uint32_t normalize_factor = 1;

  while (v4l2_range / normalize_factor > 100.0)
    normalize_factor *= 10;

  return normalize_factor;
}

class MetadataUpdater {
 public:
  explicit MetadataUpdater(android::CameraMetadata* metadata)
      : metadata_(metadata), ok_(true) {}

  bool ok() { return ok_; }

  template <typename T>
  void operator()(int tag, const std::vector<T>& data) {
    if (!ok_) {
      return;
    }
    if (metadata_->update(tag, data) != 0) {
      ok_ = false;
      LOGF(ERROR) << "Update metadata with tag " << std::hex << std::showbase
                  << tag << " failed" << std::dec;
    }
  }

  template <typename T>
  std::enable_if_t<std::is_enum<T>::value> operator()(int tag, const T& data) {
    static constexpr auto kInt32EnumTags = base::MakeFixedFlatSet<int>({
        ANDROID_DEPTH_AVAILABLE_DEPTH_STREAM_CONFIGURATIONS,
        ANDROID_SCALER_AVAILABLE_FORMATS,
        ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
        ANDROID_SENSOR_TEST_PATTERN_MODE,
        ANDROID_SYNC_MAX_LATENCY,
    });
    if (kInt32EnumTags.contains(tag)) {
      operator()(tag, std::vector<int32_t>{static_cast<int32_t>(data)});
    } else {
      operator()(tag, std::vector<uint8_t>{base::checked_cast<uint8_t>(data)});
    }
  }

  template <typename T>
  std::enable_if_t<!std::is_enum<T>::value> operator()(int tag, const T& data) {
    operator()(tag, std::vector<T>{data});
  }

 private:
  android::CameraMetadata* metadata_;
  bool ok_;
};

// Checks if a fps range can be filled into aeAvailableTargetFpsRanges given a
// list of supported formats.
// Android metadata only reports min frame duration for each format/resolution.
// CTS assumes a fps range is supported if the min frame duration (1/max_fps)
// covers the range. Thus we need to check if the USB camera actually supports
// some fps in the range.
bool IsFpsRangeSupported(const SupportedFormats& supported_formats,
                         int32_t fps_range_min,
                         int32_t fps_range_max) {
  for (const auto& format : supported_formats) {
    const int32_t max_fps = static_cast<int32_t>(*std::max_element(
        format.frame_rates.begin(), format.frame_rates.end()));
    if (max_fps >= fps_range_max) {
      const bool has_fps_in_range = std::any_of(
          format.frame_rates.begin(), format.frame_rates.end(), [&](float x) {
            const int32_t fps = static_cast<int32_t>(x);
            return fps_range_min <= fps && fps <= fps_range_max;
          });
      if (!has_fps_in_range)
        return false;
    }
  }
  return true;
}

Size GetMaxDimensions(const SupportedFormats& formats) {
  uint32_t max_width = 0;
  uint32_t max_height = 0;
  for (const SupportedFormat& format : formats) {
    max_width = std::max(max_width, format.width);
    max_height = std::max(max_height, format.height);
  }
  return Size(max_width, max_height);
}

}  // namespace

MetadataHandler::MetadataHandler(const camera_metadata_t& static_metadata,
                                 const camera_metadata_t& request_template,
                                 const DeviceInfo& device_info,
                                 V4L2CameraDevice* device,
                                 const SupportedFormats& supported_formats)
    : device_info_(device_info),
      device_(device),
      af_trigger_(false),
      focus_distance_normalize_factor_(0) {
  // MetadataBase::operator= will make a copy of camera_metadata_t.
  static_metadata_ = &static_metadata;
  request_template_ = &request_template;

  max_supported_fps_ = 0;
  for (const auto& format : supported_formats) {
    for (const float& frame_rate : format.frame_rates) {
      // Since the |frame_rate| is a float, we need to round here.
      int fps = std::round(frame_rate);
      if (fps > max_supported_fps_) {
        max_supported_fps_ = fps;
      }
    }
  }

  // camera3_request_template_t starts at 1.
  for (int i = 1; i < CAMERA3_TEMPLATE_COUNT; i++) {
    template_settings_[i] = CreateDefaultRequestSettings(i);
  }

  is_awb_control_supported_ = V4L2CameraDevice::IsControlSupported(
      device_info_.device_path, kControlWhiteBalanceTemperature);
  awb_temperature_ = GetAvailableAwbTemperatures(device_info);

  is_brightness_control_supported_ = V4L2CameraDevice::IsControlSupported(
      device_info.device_path, kControlBrightness);
  is_contrast_control_supported_ = V4L2CameraDevice::IsControlSupported(
      device_info.device_path, kControlContrast);
  is_pan_control_supported_ = V4L2CameraDevice::IsControlSupported(
      device_info.device_path, kControlPan);
  is_saturation_control_supported_ = V4L2CameraDevice::IsControlSupported(
      device_info.device_path, kControlSaturation);
  is_sharpness_control_supported_ = V4L2CameraDevice::IsControlSupported(
      device_info.device_path, kControlSharpness);
  is_tilt_control_supported_ = V4L2CameraDevice::IsControlSupported(
      device_info.device_path, kControlTilt);
  is_zoom_control_supported_ = V4L2CameraDevice::IsControlSupported(
      device_info.device_path, kControlZoom);

  if (V4L2CameraDevice::IsFocusDistanceSupported(device_info.device_path,
                                                 &focus_distance_range_)) {
    float full_range =
        focus_distance_range_.maximum - focus_distance_range_.minimum;
    focus_distance_normalize_factor_ =
        GetNormalizeFactorForV4l2FocusRange(full_range);
  }

  thread_checker_.DetachFromThread();
}

MetadataHandler::~MetadataHandler() {}

int MetadataHandler::FillDefaultMetadata(
    android::CameraMetadata* static_metadata,
    android::CameraMetadata* request_metadata) {
  MetadataUpdater update_static(static_metadata);
  MetadataUpdater update_request(request_metadata);

  // android.colorCorrection
  update_static(ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES,
                std::vector<uint8_t>{
                    ANDROID_COLOR_CORRECTION_ABERRATION_MODE_FAST,
                    ANDROID_COLOR_CORRECTION_ABERRATION_MODE_HIGH_QUALITY});
  update_request(ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
                 ANDROID_COLOR_CORRECTION_ABERRATION_MODE_FAST);

  // android.control
  // We don't support AE compensation.
  update_static(ANDROID_CONTROL_AE_COMPENSATION_RANGE,
                std::vector<int32_t>{0, 0});

  update_static(ANDROID_CONTROL_AE_COMPENSATION_STEP,
                camera_metadata_rational_t{0, 1});

  update_static(ANDROID_CONTROL_MAX_REGIONS,
                std::vector<int32_t>{/*AE*/ 0, /*AWB*/ 0, /*AF*/ 0});

  update_static(ANDROID_CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES,
                ANDROID_CONTROL_VIDEO_STABILIZATION_MODE_OFF);
  update_request(ANDROID_CONTROL_VIDEO_STABILIZATION_MODE,
                 ANDROID_CONTROL_VIDEO_STABILIZATION_MODE_OFF);

  update_static(ANDROID_CONTROL_AWB_AVAILABLE_MODES,
                ANDROID_CONTROL_AWB_MODE_AUTO);
  update_request(ANDROID_CONTROL_AWB_MODE, ANDROID_CONTROL_AWB_MODE_AUTO);

  update_static(ANDROID_CONTROL_AE_AVAILABLE_MODES, ANDROID_CONTROL_AE_MODE_ON);
  // ON means auto-exposure is active with no flash control.
  update_request(ANDROID_CONTROL_AE_MODE, ANDROID_CONTROL_AE_MODE_ON);

  update_request(ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION, int32_t{0});

  update_request(ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER,
                 ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER_IDLE);

  update_request(ANDROID_CONTROL_AF_TRIGGER, ANDROID_CONTROL_AF_TRIGGER_IDLE);

  update_static(ANDROID_CONTROL_AVAILABLE_SCENE_MODES,
                ANDROID_CONTROL_SCENE_MODE_DISABLED);
  update_request(ANDROID_CONTROL_SCENE_MODE,
                 ANDROID_CONTROL_SCENE_MODE_DISABLED);

  update_static(ANDROID_CONTROL_AVAILABLE_EFFECTS,
                ANDROID_CONTROL_EFFECT_MODE_OFF);
  update_request(ANDROID_CONTROL_EFFECT_MODE, ANDROID_CONTROL_EFFECT_MODE_OFF);

  update_static(ANDROID_CONTROL_AE_LOCK_AVAILABLE,
                ANDROID_CONTROL_AE_LOCK_AVAILABLE_FALSE);

  update_static(ANDROID_CONTROL_AWB_LOCK_AVAILABLE,
                ANDROID_CONTROL_AWB_LOCK_AVAILABLE_FALSE);

  update_static(ANDROID_CONTROL_AVAILABLE_MODES,
                std::vector<uint8_t>{ANDROID_CONTROL_MODE_OFF,
                                     ANDROID_CONTROL_MODE_AUTO});

  // android.flash
  update_static(ANDROID_FLASH_INFO_AVAILABLE,
                ANDROID_FLASH_INFO_AVAILABLE_FALSE);
  update_request(ANDROID_FLASH_STATE, ANDROID_FLASH_STATE_UNAVAILABLE);
  update_request(ANDROID_FLASH_MODE, ANDROID_FLASH_MODE_OFF);

  // android.jpeg
  update_static(ANDROID_JPEG_MAX_SIZE, int32_t{13 << 20});
  update_request(ANDROID_JPEG_QUALITY, uint8_t{90});
  update_request(ANDROID_JPEG_THUMBNAIL_QUALITY, uint8_t{90});
  update_request(ANDROID_JPEG_ORIENTATION, int32_t{0});

  // android.lens
  // This should not be needed.
  update_static(ANDROID_LENS_INFO_HYPERFOCAL_DISTANCE, 0.0f);
  update_static(ANDROID_LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION,
                ANDROID_LENS_OPTICAL_STABILIZATION_MODE_OFF);
  update_request(ANDROID_LENS_OPTICAL_STABILIZATION_MODE,
                 ANDROID_LENS_OPTICAL_STABILIZATION_MODE_OFF);

  // android.noiseReduction
  update_static(ANDROID_NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES,
                ANDROID_NOISE_REDUCTION_MODE_OFF);
  update_request(ANDROID_NOISE_REDUCTION_MODE,
                 ANDROID_NOISE_REDUCTION_MODE_OFF);

  // android.request
  update_static(ANDROID_REQUEST_AVAILABLE_CAPABILITIES,
                ANDROID_REQUEST_AVAILABLE_CAPABILITIES_BACKWARD_COMPATIBLE);
  update_static(ANDROID_REQUEST_PARTIAL_RESULT_COUNT, int32_t{1});

  // This means pipeline latency of X frame intervals. The maximum number is 4.
  update_static(ANDROID_REQUEST_PIPELINE_MAX_DEPTH, uint8_t{4});
  update_request(ANDROID_REQUEST_PIPELINE_DEPTH, uint8_t{4});

  // Three numbers represent the maximum numbers of different types of output
  // streams simultaneously. The types are raw sensor, processed (but not
  // stalling), and processed (but stalling). For usb limited mode, raw sensor
  // is not supported. Stalling stream is JPEG. Non-stalling streams are
  // YUV_420_888, NV21, or YV12.
  update_static(ANDROID_REQUEST_MAX_NUM_OUTPUT_STREAMS,
                std::vector<int32_t>{0, 2, 1});

  // Limited mode doesn't support reprocessing.
  update_static(ANDROID_REQUEST_MAX_NUM_INPUT_STREAMS, int32_t{0});

  // android.scaler
  update_static(ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM, 1.0f);

  update_static(ANDROID_SCALER_CROPPING_TYPE,
                ANDROID_SCALER_CROPPING_TYPE_CENTER_ONLY);

  update_static(ANDROID_SENSOR_AVAILABLE_TEST_PATTERN_MODES,
                std::vector<int32_t>{
                    ANDROID_SENSOR_TEST_PATTERN_MODE_OFF,
                    ANDROID_SENSOR_TEST_PATTERN_MODE_COLOR_BARS_FADE_TO_GRAY});
  update_request(ANDROID_SENSOR_TEST_PATTERN_MODE,
                 ANDROID_SENSOR_TEST_PATTERN_MODE_OFF);

  uint8_t timestamp_source;
  if (V4L2CameraDevice::GetUvcClock() == CLOCK_BOOTTIME) {
    timestamp_source = ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE_REALTIME;
  } else {
    timestamp_source = ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE_UNKNOWN;
  }
  update_static(ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE, timestamp_source);

  // android.shading
  update_static(ANDROID_SHADING_AVAILABLE_MODES, ANDROID_SHADING_MODE_FAST);

  // android.statistics
  update_static(ANDROID_STATISTICS_INFO_AVAILABLE_HOT_PIXEL_MAP_MODES,
                ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE_OFF);
  update_request(ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE,
                 ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE_OFF);

  update_static(ANDROID_STATISTICS_INFO_AVAILABLE_LENS_SHADING_MAP_MODES,
                ANDROID_STATISTICS_LENS_SHADING_MAP_MODE_OFF);

  // android.sync
  update_static(ANDROID_SYNC_MAX_LATENCY, ANDROID_SYNC_MAX_LATENCY_UNKNOWN);

  // Allowed configuration in session parameters
  update_static(ANDROID_REQUEST_AVAILABLE_SESSION_KEYS,
                std::vector<int32_t>{ANDROID_CONTROL_AE_TARGET_FPS_RANGE});

  return update_static.ok() && update_request.ok() ? 0 : -EINVAL;
}

int MetadataHandler::FillMetadataFromSupportedFormats(
    const SupportedFormats& supported_formats,
    const DeviceInfo& device_info,
    android::CameraMetadata* static_metadata,
    android::CameraMetadata* request_metadata) {
  bool is_external = device_info.lens_facing == LensFacing::kExternal;
  bool is_builtin = !is_external;
  bool is_v1_builtin = device_info.quirks & kQuirkV1Device;

  if (supported_formats.empty()) {
    LOGF(ERROR)
        << "Failed to fill metadata since there is no supported formats";
    return -EINVAL;
  }
  std::vector<int32_t> stream_configurations;
  std::vector<int64_t> min_frame_durations;
  std::vector<int64_t> stall_durations;

  // The min fps <= 15 must be supported in CTS.
  const int64_t kOneSecOfNanoUnit = 1000000000LL;
  int32_t max_fps = std::numeric_limits<int32_t>::min();
  int64_t max_frame_duration = kOneSecOfNanoUnit / kMinFps;
  std::set<int32_t> supported_fps;

  std::vector<int> hal_formats{HAL_PIXEL_FORMAT_BLOB,
                               HAL_PIXEL_FORMAT_YCbCr_420_888,
                               HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED};

  std::unique_ptr<CameraConfig> camera_config =
      CameraConfig::Create(constants::kCrosCameraConfigPathString);
  int max_width = camera_config->GetInteger(constants::kCrosUsbMaxStreamWidth,
                                            std::numeric_limits<int>::max());
  int max_height = camera_config->GetInteger(constants::kCrosUsbMaxStreamHeight,
                                             std::numeric_limits<int>::max());
  for (const auto& supported_format : supported_formats) {
    int64_t min_frame_duration = std::numeric_limits<int64_t>::max();
    int32_t per_format_max_fps = std::numeric_limits<int32_t>::min();
    for (const auto& frame_rate : supported_format.frame_rates) {
      // To prevent floating point precision problem we cast the floating point
      // to double here.
      int64_t frame_duration =
          kOneSecOfNanoUnit / static_cast<double>(frame_rate);
      if (frame_duration < min_frame_duration) {
        min_frame_duration = frame_duration;
      }
      if (frame_duration > max_frame_duration) {
        max_frame_duration = frame_duration;
      }
      if (per_format_max_fps < static_cast<int32_t>(frame_rate)) {
        per_format_max_fps = static_cast<int32_t>(frame_rate);
      }
      supported_fps.insert(frame_rate);
    }
    if (per_format_max_fps > max_fps) {
      max_fps = per_format_max_fps;
    }

    for (const auto& format : hal_formats) {
      if (is_builtin) {
        if (format != HAL_PIXEL_FORMAT_BLOB) {
          if (per_format_max_fps < 30) {
            continue;
          }
          if (supported_format.width > max_width ||
              supported_format.height > max_height) {
            LOGF(INFO) << "Filter Format: 0x" << std::hex << format << std::dec
                       << "-" << supported_format.width << "x"
                       << supported_format.height;
            continue;
          }
        }
      }

      stream_configurations.push_back(format);
      stream_configurations.push_back(supported_format.width);
      stream_configurations.push_back(supported_format.height);
      stream_configurations.push_back(
          ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS_OUTPUT);

      min_frame_durations.push_back(format);
      min_frame_durations.push_back(supported_format.width);
      min_frame_durations.push_back(supported_format.height);
      min_frame_durations.push_back(min_frame_duration);
    }

    // The stall duration is 0 for non-jpeg formats. For JPEG format, stall
    // duration can be 0 if JPEG is small. 5MP JPEG takes 700ms to decode
    // and encode. Here we choose 1 sec for JPEG.
    for (const auto& format : hal_formats) {
      // For non-jpeg formats, the camera orientation workaround crops,
      // rotates, and scales the frames. Theoretically the stall duration of
      // huge resolution may be bigger than 0. Set it to 0 for now.
      int64_t stall_duration =
          (format == HAL_PIXEL_FORMAT_BLOB) ? 1000000000 : 0;
      stall_durations.push_back(format);
      stall_durations.push_back(supported_format.width);
      stall_durations.push_back(supported_format.height);
      stall_durations.push_back(stall_duration);
    }
  }

  MetadataUpdater update_static(static_metadata);
  MetadataUpdater update_request(request_metadata);

  // The document in aeAvailableTargetFpsRanges section says the min fps should
  // not be larger than 15.
  // We enumerate all possible fps and put (min, fps) as available fps range. If
  // the device support constant frame rate, put (fps, fps) into the list as
  // well.
  // TODO(wtlee): Handle non-integer fps when setting controls.
  bool support_constant_framerate = !device_info.constant_framerate_unsupported;
  std::vector<int32_t> available_fps_ranges;

  // For devices that cannot actually meet the fps ranges they report, only
  // report (min, max) and optional (max, max) if they support constant frame
  // rate.
  if (device_info.quirks & kQuirkReportLeastFpsRanges) {
    available_fps_ranges.push_back(kMinFps);
    available_fps_ranges.push_back(max_fps);

    if (support_constant_framerate) {
      available_fps_ranges.push_back(max_fps);
      available_fps_ranges.push_back(max_fps);
    }
  } else {
    for (auto fps : supported_fps) {
      // The IsFpsRangeSupported() filter should only apply on built-in
      // cameras, otherwise some webcams with fps combinations that cannot be
      // represented in HALv3 API would stop working (b/171845790).
      if (is_external || IsFpsRangeSupported(supported_formats, kMinFps, fps)) {
        available_fps_ranges.push_back(kMinFps);
        available_fps_ranges.push_back(fps);
      }

      if (support_constant_framerate &&
          (is_external || IsFpsRangeSupported(supported_formats, fps, fps))) {
        available_fps_ranges.push_back(fps);
        available_fps_ranges.push_back(fps);
      }
    }
  }
  update_static(ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES,
                available_fps_ranges);
  update_static(ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
                stream_configurations);
  update_static(ANDROID_SCALER_AVAILABLE_MIN_FRAME_DURATIONS,
                min_frame_durations);
  update_static(ANDROID_SCALER_AVAILABLE_STALL_DURATIONS, stall_durations);

  std::vector<int32_t> jpeg_available_thumbnail_sizes =
      GetJpegAvailableThumbnailSizes(supported_formats);
  update_static(ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES,
                jpeg_available_thumbnail_sizes);
  update_request(ANDROID_JPEG_THUMBNAIL_SIZE,
                 std::vector<int32_t>(jpeg_available_thumbnail_sizes.end() - 2,
                                      jpeg_available_thumbnail_sizes.end()));
  update_static(ANDROID_SENSOR_INFO_MAX_FRAME_DURATION, max_frame_duration);

  const Size max_dimensions = GetMaxDimensions(supported_formats);
  std::vector<int32_t> active_array_size(4);
  if (device_info.sensor_info_active_array_size.is_valid()) {
    const Rect<int32_t>& rect = device_info.sensor_info_active_array_size;
    if (rect.width < max_dimensions.width ||
        rect.height < max_dimensions.height) {
      LOGF(ERROR) << "Sensor active array size (" << rect.width << "x"
                  << rect.height
                  << ") is smaller than max supported format dimensions ("
                  << max_dimensions.width << "x" << max_dimensions.height
                  << ")";
      return -EINVAL;
    }
    active_array_size[0] = rect.left;
    active_array_size[1] = rect.top;
    active_array_size[2] = rect.width;
    active_array_size[3] = rect.height;
  } else {
    active_array_size[0] = 0;
    active_array_size[1] = 0;
    active_array_size[2] = static_cast<int32_t>(max_dimensions.width);
    active_array_size[3] = static_cast<int32_t>(max_dimensions.height);
  }
  update_static(ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE,
                active_array_size);
  update_static(ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE, active_array_size);

  if (is_v1_builtin) {
    if (FillSensorInfo(device_info, static_metadata,
                       static_cast<int32_t>(max_dimensions.width),
                       static_cast<int32_t>(max_dimensions.height)) != 0) {
      LOGF(ERROR) << "Failed to fill sensor info for v1 built-in camera";
      return -EINVAL;
    }
  } else if (is_external) {
    // It's a sensible value for external camera, since it's required on all
    // devices per spec. For built-in camera, this would be filled in
    // FillMetadataFromDeviceInfo() or FillSensorInfo() using the value from the
    // configuration file.
    //
    // The official document for this field:
    // https://developer.android.com/reference/android/hardware/camera2/CameraCharacteristics.html#SENSOR_INFO_PIXEL_ARRAY_SIZE
    if (device_info.sensor_info_pixel_array_size_width > 0 &&
        device_info.sensor_info_pixel_array_size_height > 0) {
      update_static(ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE,
                    std::vector<int32_t>{
                        device_info.sensor_info_pixel_array_size_width,
                        device_info.sensor_info_pixel_array_size_height});
    } else {
      update_static(
          ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE,
          std::vector<int32_t>{active_array_size[2], active_array_size[3]});
    }
  }

  return update_static.ok() && update_request.ok() ? 0 : -EINVAL;
}

// static
AwbModeToTemperatureMap MetadataHandler::GetAvailableAwbTemperatures(
    const DeviceInfo& device_info) {
  AwbModeToTemperatureMap available_awb_temperatures;

  available_awb_temperatures[ANDROID_CONTROL_AWB_MODE_AUTO] =
      kColorTemperatureAuto;

  if (!V4L2CameraDevice::IsControlSupported(device_info.device_path,
                                            kControlAutoWhiteBalance))
    return available_awb_temperatures;

  ControlInfo info;
  if (V4L2CameraDevice::QueryControl(
          device_info.device_path, kControlWhiteBalanceTemperature, &info) != 0)
    return available_awb_temperatures;

  for (auto& mode_temperature : GetAwbModeTemperatureMap()) {
    uint32_t temperature =
        GetAwbTemperatureByMode(info.range, mode_temperature.first);
    if (!temperature)
      continue;
    available_awb_temperatures[mode_temperature.first] = temperature;
  }

  return available_awb_temperatures;
}

// static
int MetadataHandler::FillMetadataFromDeviceInfo(
    const DeviceInfo& device_info,
    android::CameraMetadata* static_metadata,
    android::CameraMetadata* request_metadata) {
  MetadataUpdater update_static(static_metadata);
  MetadataUpdater update_request(request_metadata);

  bool is_external = device_info.lens_facing == LensFacing::kExternal;
  bool is_builtin = !is_external;
  bool is_v1_builtin = device_info.quirks & kQuirkV1Device;
  bool is_v3_builtin = is_builtin && !is_v1_builtin;

  std::vector<int32_t> available_request_keys = {
      ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
      ANDROID_CONTROL_AE_ANTIBANDING_MODE,
      ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
      ANDROID_CONTROL_AE_LOCK,
      ANDROID_CONTROL_AE_MODE,
      ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER,
      ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
      ANDROID_CONTROL_AF_MODE,
      ANDROID_CONTROL_AF_TRIGGER,
      ANDROID_CONTROL_AWB_LOCK,
      ANDROID_CONTROL_AWB_MODE,
      ANDROID_CONTROL_CAPTURE_INTENT,
      ANDROID_CONTROL_EFFECT_MODE,
      ANDROID_CONTROL_MODE,
      ANDROID_CONTROL_SCENE_MODE,
      ANDROID_CONTROL_VIDEO_STABILIZATION_MODE,
      ANDROID_FLASH_MODE,
      ANDROID_JPEG_ORIENTATION,
      ANDROID_JPEG_QUALITY,
      ANDROID_JPEG_THUMBNAIL_QUALITY,
      ANDROID_JPEG_THUMBNAIL_SIZE,
      ANDROID_LENS_OPTICAL_STABILIZATION_MODE,
      ANDROID_NOISE_REDUCTION_MODE,
      ANDROID_SCALER_CROP_REGION,
      ANDROID_SENSOR_TEST_PATTERN_MODE,
      ANDROID_STATISTICS_FACE_DETECT_MODE,
      ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE,
  };
  if (is_builtin) {
    available_request_keys.insert(available_request_keys.end(),
                                  {
                                      ANDROID_LENS_APERTURE,
                                      ANDROID_LENS_FOCAL_LENGTH,
                                      ANDROID_LENS_FOCUS_DISTANCE,
                                  });
  }

  // TODO(shik): All properties listed for capture requests can also be queried
  // on the capture result, to determine the final values used for capture. We
  // shuold build this list from |available_request_keys|.
  // ref:
  // https://developer.android.com/reference/android/hardware/camera2/CaptureResult
  std::vector<int32_t> available_result_keys = {
      ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
      ANDROID_CONTROL_AE_ANTIBANDING_MODE,
      ANDROID_CONTROL_AE_EXPOSURE_COMPENSATION,
      ANDROID_CONTROL_AE_LOCK,
      ANDROID_CONTROL_AE_MODE,
      ANDROID_CONTROL_AE_PRECAPTURE_TRIGGER,
      ANDROID_CONTROL_AE_STATE,
      ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
      ANDROID_CONTROL_AF_MODE,
      ANDROID_CONTROL_AF_STATE,
      ANDROID_CONTROL_AF_TRIGGER,
      ANDROID_CONTROL_AWB_LOCK,
      ANDROID_CONTROL_AWB_MODE,
      ANDROID_CONTROL_AWB_STATE,
      ANDROID_CONTROL_CAPTURE_INTENT,
      ANDROID_CONTROL_EFFECT_MODE,
      ANDROID_CONTROL_MODE,
      ANDROID_CONTROL_SCENE_MODE,
      ANDROID_CONTROL_VIDEO_STABILIZATION_MODE,
      ANDROID_FLASH_MODE,
      ANDROID_FLASH_STATE,
      ANDROID_JPEG_ORIENTATION,
      ANDROID_JPEG_QUALITY,
      ANDROID_JPEG_THUMBNAIL_QUALITY,
      ANDROID_JPEG_THUMBNAIL_SIZE,
      ANDROID_LENS_OPTICAL_STABILIZATION_MODE,
      ANDROID_LENS_STATE,
      ANDROID_NOISE_REDUCTION_MODE,
      ANDROID_REQUEST_PIPELINE_DEPTH,
      ANDROID_SCALER_CROP_REGION,
      ANDROID_SENSOR_EXPOSURE_TIME,
      ANDROID_SENSOR_ROLLING_SHUTTER_SKEW,
      ANDROID_SENSOR_TEST_PATTERN_MODE,
      ANDROID_SENSOR_TIMESTAMP,
      ANDROID_STATISTICS_FACE_DETECT_MODE,
      ANDROID_STATISTICS_HOT_PIXEL_MAP_MODE,
      ANDROID_STATISTICS_LENS_SHADING_MAP_MODE,
      ANDROID_STATISTICS_SCENE_FLICKER,
  };
  if (is_builtin) {
    available_result_keys.insert(available_result_keys.end(),
                                 {
                                     ANDROID_LENS_APERTURE,
                                     ANDROID_LENS_FOCAL_LENGTH,
                                     ANDROID_LENS_FOCUS_DISTANCE,
                                 });
  }

  // TODO(shik): The HAL must not have any tags in its static info that are not
  // listed either here or in the vendor tag list.  Some request/result metadata
  // entries are also presented in the static info now, and we should fix it.
  // ref:
  // https://android.googlesource.com/platform/system/media/+/a8cff157ff0ed02fa7e29438f4889a9933c37768/camera/docs/docs.html#16298
  std::vector<int32_t> available_characteristics_keys = {
      ANDROID_COLOR_CORRECTION_AVAILABLE_ABERRATION_MODES,
      ANDROID_CONTROL_AE_AVAILABLE_ANTIBANDING_MODES,
      ANDROID_CONTROL_AE_AVAILABLE_MODES,
      ANDROID_CONTROL_AE_AVAILABLE_TARGET_FPS_RANGES,
      ANDROID_CONTROL_AE_COMPENSATION_RANGE,
      ANDROID_CONTROL_AE_COMPENSATION_STEP,
      ANDROID_CONTROL_AE_LOCK_AVAILABLE,
      ANDROID_CONTROL_AF_AVAILABLE_MODES,
      ANDROID_CONTROL_AVAILABLE_EFFECTS,
      ANDROID_CONTROL_AVAILABLE_MODES,
      ANDROID_CONTROL_AVAILABLE_SCENE_MODES,
      ANDROID_CONTROL_AVAILABLE_VIDEO_STABILIZATION_MODES,
      ANDROID_CONTROL_AWB_AVAILABLE_MODES,
      ANDROID_CONTROL_AWB_LOCK_AVAILABLE,
      ANDROID_CONTROL_MAX_REGIONS,
      ANDROID_FLASH_INFO_AVAILABLE,
      ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL,
      ANDROID_JPEG_AVAILABLE_THUMBNAIL_SIZES,
      ANDROID_JPEG_MAX_SIZE,
      ANDROID_LENS_FACING,
      ANDROID_LENS_INFO_AVAILABLE_OPTICAL_STABILIZATION,
      ANDROID_LENS_INFO_FOCUS_DISTANCE_CALIBRATION,
      ANDROID_LENS_INFO_HYPERFOCAL_DISTANCE,
      ANDROID_LENS_INFO_MINIMUM_FOCUS_DISTANCE,
      ANDROID_NOISE_REDUCTION_AVAILABLE_NOISE_REDUCTION_MODES,
      ANDROID_REQUEST_AVAILABLE_CAPABILITIES,
      ANDROID_REQUEST_MAX_NUM_INPUT_STREAMS,
      ANDROID_REQUEST_MAX_NUM_OUTPUT_STREAMS,
      ANDROID_REQUEST_PARTIAL_RESULT_COUNT,
      ANDROID_REQUEST_PIPELINE_MAX_DEPTH,
      ANDROID_SCALER_AVAILABLE_MAX_DIGITAL_ZOOM,
      ANDROID_SCALER_AVAILABLE_STREAM_CONFIGURATIONS,
      ANDROID_SCALER_CROPPING_TYPE,
      ANDROID_SENSOR_AVAILABLE_TEST_PATTERN_MODES,
      ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE,
      ANDROID_SENSOR_INFO_MAX_FRAME_DURATION,
      ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE,
      ANDROID_SENSOR_INFO_PRE_CORRECTION_ACTIVE_ARRAY_SIZE,
      ANDROID_SENSOR_INFO_TIMESTAMP_SOURCE,
      ANDROID_SENSOR_ORIENTATION,
      ANDROID_SHADING_AVAILABLE_MODES,
      ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES,
      ANDROID_STATISTICS_INFO_AVAILABLE_HOT_PIXEL_MAP_MODES,
      ANDROID_STATISTICS_INFO_AVAILABLE_LENS_SHADING_MAP_MODES,
      ANDROID_STATISTICS_INFO_MAX_FACE_COUNT,
      ANDROID_SYNC_MAX_LATENCY,
  };
  if (is_builtin) {
    if (!device_info.lens_info_available_apertures.empty()) {
      // This field is optional. Only list it if it presents in the
      // configuration.
      available_characteristics_keys.insert(
          available_characteristics_keys.end(),
          {
              ANDROID_LENS_INFO_AVAILABLE_APERTURES,
          });
    }
    available_characteristics_keys.insert(
        available_characteristics_keys.end(),
        {
            ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS,
            ANDROID_SENSOR_INFO_PHYSICAL_SIZE,
        });
  }

  update_static(ANDROID_SENSOR_ORIENTATION, device_info.sensor_orientation);
  update_static(ANDROID_LENS_FACING,
                static_cast<uint8_t>(device_info.lens_facing));

  if (is_v3_builtin) {
    update_static(ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL,
                  ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_LIMITED);

    update_static(ANDROID_LENS_INFO_AVAILABLE_APERTURES,
                  device_info.lens_info_available_apertures);

    update_request(ANDROID_LENS_APERTURE,
                   device_info.lens_info_available_apertures[0]);

    update_static(ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS,
                  device_info.lens_info_available_focal_lengths);

    update_request(ANDROID_LENS_FOCAL_LENGTH,
                   device_info.lens_info_available_focal_lengths[0]);

    update_static(
        ANDROID_SENSOR_INFO_PHYSICAL_SIZE,
        std::vector<float>{device_info.sensor_info_physical_size_width,
                           device_info.sensor_info_physical_size_height});
    update_static(
        ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE,
        std::vector<int32_t>{device_info.sensor_info_pixel_array_size_width,
                             device_info.sensor_info_pixel_array_size_height});
  } else if (is_v1_builtin) {
    update_static(ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL,
                  ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL);

    if (device_info.lens_info_available_apertures.size() > 0) {
      update_static(ANDROID_LENS_INFO_AVAILABLE_APERTURES,
                    device_info.lens_info_available_apertures);
      update_request(ANDROID_LENS_APERTURE,
                     device_info.lens_info_available_apertures[0]);
    }

    if (device_info.lens_info_available_focal_lengths.size() > 0) {
      update_static(ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS,
                    device_info.lens_info_available_focal_lengths);
      update_request(ANDROID_LENS_FOCAL_LENGTH,
                     device_info.lens_info_available_focal_lengths[0]);
    } else {
      update_static(ANDROID_LENS_INFO_AVAILABLE_FOCAL_LENGTHS,
                    kDefaultAvailableFocalLength);
      update_request(ANDROID_LENS_FOCAL_LENGTH, kDefaultAvailableFocalLength);
    }

    if (device_info.sensor_info_pixel_array_size_width > 0 &&
        device_info.sensor_info_pixel_array_size_height > 0) {
      update_static(ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE,
                    std::vector<int32_t>{
                        device_info.sensor_info_pixel_array_size_width,
                        device_info.sensor_info_pixel_array_size_height});
    }
    // For |sensor_info_physical_size|, fill them later with supported formats
    // information.
  } else {
    update_static(ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL,
                  ANDROID_INFO_SUPPORTED_HARDWARE_LEVEL_EXTERNAL);
  }

  update_static(ANDROID_CONTROL_AE_AVAILABLE_ANTIBANDING_MODES,
                ANDROID_CONTROL_AE_ANTIBANDING_MODE_AUTO);
  update_request(ANDROID_CONTROL_AE_ANTIBANDING_MODE,
                 ANDROID_CONTROL_AE_ANTIBANDING_MODE_AUTO);

  ControlInfo info;

  if (V4L2CameraDevice::QueryControl(device_info.device_path,
                                     kControlBrightness, &info) == 0) {
    update_static(kVendorTagControlBrightnessRange,
                  std::vector<int32_t>{info.range.minimum, info.range.maximum,
                                       info.range.step});
    update_static(kVendorTagControlBrightnessDefault,
                  std::vector<int32_t>{info.range.default_value});
  }

  if (V4L2CameraDevice::QueryControl(device_info.device_path, kControlContrast,
                                     &info) == 0) {
    update_static(kVendorTagControlContrastRange,
                  std::vector<int32_t>{info.range.minimum, info.range.maximum,
                                       info.range.step});
    update_static(kVendorTagControlContrastDefault,
                  std::vector<int32_t>{info.range.default_value});
  }

  if (V4L2CameraDevice::QueryControl(device_info.device_path, kControlPan,
                                     &info) == 0) {
    update_static(kVendorTagControlPanRange,
                  std::vector<int32_t>{info.range.minimum, info.range.maximum,
                                       info.range.step});
    update_static(kVendorTagControlPanDefault,
                  std::vector<int32_t>{info.range.default_value});
  }

  if (V4L2CameraDevice::QueryControl(device_info.device_path,
                                     kControlSaturation, &info) == 0) {
    update_static(kVendorTagControlSaturationRange,
                  std::vector<int32_t>{info.range.minimum, info.range.maximum,
                                       info.range.step});
    update_static(kVendorTagControlSaturationDefault,
                  std::vector<int32_t>{info.range.default_value});
  }

  if (V4L2CameraDevice::QueryControl(device_info.device_path, kControlSharpness,
                                     &info) == 0) {
    update_static(kVendorTagControlSharpnessRange,
                  std::vector<int32_t>{info.range.minimum, info.range.maximum,
                                       info.range.step});
    update_static(kVendorTagControlSharpnessDefault,
                  std::vector<int32_t>{info.range.default_value});
  }

  if (V4L2CameraDevice::QueryControl(device_info.device_path, kControlTilt,
                                     &info) == 0) {
    update_static(kVendorTagControlTiltRange,
                  std::vector<int32_t>{info.range.minimum, info.range.maximum,
                                       info.range.step});
    update_static(kVendorTagControlTiltDefault,
                  std::vector<int32_t>{info.range.default_value});
  }

  if (V4L2CameraDevice::QueryControl(device_info.device_path, kControlZoom,
                                     &info) == 0) {
    update_static(kVendorTagControlZoomRange,
                  std::vector<int32_t>{info.range.minimum, info.range.maximum,
                                       info.range.step});
    update_static(kVendorTagControlZoomDefault,
                  std::vector<int32_t>{info.range.default_value});
  }

  std::vector<uint8_t> available_awb_modes;
  for (auto const& it : GetAvailableAwbTemperatures(device_info))
    available_awb_modes.push_back(it.first);

  update_static(ANDROID_CONTROL_AWB_AVAILABLE_MODES, available_awb_modes);

  // Check if device supports manual exposure control.
  ControlRange range;
  if (V4L2CameraDevice::IsManualExposureTimeSupported(device_info.device_path,
                                                      &range)) {
    update_static(ANDROID_CONTROL_AE_AVAILABLE_MODES,
                  std::vector<uint8_t>{ANDROID_CONTROL_AE_MODE_OFF,
                                       ANDROID_CONTROL_AE_MODE_ON});
    // The unit of the range is 100 us.
    update_static(ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE,
                  std::vector<int64_t>{
                      range.minimum * 100 * 1000 /* ns */,
                      range.maximum * 100 * 1000 /* ns */
                  });
    available_characteristics_keys.push_back(
        ANDROID_SENSOR_INFO_EXPOSURE_TIME_RANGE);
    // CtsCameraTestCases needs it. This control is only effective if
    // android.control.aeMode is set to OFF.
    update_request(
        ANDROID_SENSOR_EXPOSURE_TIME,
        static_cast<int64_t>(range.default_value) * 100 * 1000 /* ns */);
    available_request_keys.push_back(ANDROID_SENSOR_EXPOSURE_TIME);
  }

  // The unit of V4L2 focus distance is undefined, so set it to uncalibrated.
  update_static(ANDROID_LENS_INFO_FOCUS_DISTANCE_CALIBRATION,
                ANDROID_LENS_INFO_FOCUS_DISTANCE_CALIBRATION_UNCALIBRATED);
  if (V4L2CameraDevice::IsControlSupported(device_info.device_path,
                                           kControlFocusAuto)) {
    update_static(ANDROID_CONTROL_AF_AVAILABLE_MODES,
                  std::vector<uint8_t>{ANDROID_CONTROL_AF_MODE_OFF,
                                       ANDROID_CONTROL_AF_MODE_AUTO});
    update_request(ANDROID_CONTROL_AF_MODE, ANDROID_CONTROL_AF_MODE_AUTO);
    update_request(ANDROID_LENS_FOCUS_DISTANCE, 0.0f);
    if (V4L2CameraDevice::IsFocusDistanceSupported(device_info.device_path,
                                                   &range)) {
      float full_range = range.maximum - range.minimum;
      uint32_t factor = GetNormalizeFactorForV4l2FocusRange(full_range);
      update_static(ANDROID_LENS_INFO_MINIMUM_FOCUS_DISTANCE,
                    full_range / factor);
    } else {
      if (device_info.lens_info_minimum_focus_distance > 0) {
        update_static(ANDROID_LENS_INFO_MINIMUM_FOCUS_DISTANCE,
                      1.0f / device_info.lens_info_minimum_focus_distance);
      } else {
        update_static(ANDROID_LENS_INFO_MINIMUM_FOCUS_DISTANCE,
                      1.0f / kDefaultMinimumFocusDistance);
      }
    }
  } else {
    update_static(ANDROID_CONTROL_AF_AVAILABLE_MODES,
                  ANDROID_CONTROL_AF_MODE_OFF);
    update_request(ANDROID_CONTROL_AF_MODE, ANDROID_CONTROL_AF_MODE_OFF);
    update_static(ANDROID_LENS_INFO_MINIMUM_FOCUS_DISTANCE, 0.0f);
  }

  update_static(ANDROID_REQUEST_AVAILABLE_CHARACTERISTICS_KEYS,
                available_characteristics_keys);
  update_static(ANDROID_REQUEST_AVAILABLE_REQUEST_KEYS, available_request_keys);
  update_static(ANDROID_REQUEST_AVAILABLE_RESULT_KEYS, available_result_keys);

  // Sets face detection.
  if (device_info.enable_face_detection) {
    update_static(
        ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES,
        std::vector<uint8_t>{ANDROID_STATISTICS_FACE_DETECT_MODE_OFF,
                             ANDROID_STATISTICS_FACE_DETECT_MODE_SIMPLE});
    // FaceSSD can detect more than 600 faces in one 320x320 image.
    // 100 is enough for our use cases.
    update_static(ANDROID_STATISTICS_INFO_MAX_FACE_COUNT, 100);
  } else {
    update_static(
        ANDROID_STATISTICS_INFO_AVAILABLE_FACE_DETECT_MODES,
        std::vector<uint8_t>{ANDROID_STATISTICS_FACE_DETECT_MODE_OFF});
    update_static(ANDROID_STATISTICS_INFO_MAX_FACE_COUNT, 0);
  }
  update_request(ANDROID_STATISTICS_FACE_DETECT_MODE,
                 ANDROID_STATISTICS_FACE_DETECT_MODE_OFF);

  return update_static.ok() && update_request.ok() ? 0 : -EINVAL;
}

int MetadataHandler::FillSensorInfo(const DeviceInfo& device_info,
                                    android::CameraMetadata* metadata,
                                    int32_t array_width,
                                    int32_t array_height) {
  MetadataUpdater update_static(metadata);

  if (device_info.sensor_info_pixel_array_size_width <= 0 ||
      device_info.sensor_info_pixel_array_size_height <= 0) {
    update_static(ANDROID_SENSOR_INFO_PIXEL_ARRAY_SIZE,
                  std::vector<int32_t>{array_width, array_height});
  }

  float focal_length = device_info.lens_info_available_focal_lengths.size() > 0
                           ? device_info.lens_info_available_focal_lengths[0]
                           : kDefaultAvailableFocalLength;

  float aspect_ratio = 1.f * array_width / array_height;
  bool is_closer_to_16_9 = std::fabs(aspect_ratio - 16.f / 9.f) <
                           std::fabs(aspect_ratio - 4.f / 3.f);
  bool has_fov_info_16_9 = device_info.horizontal_view_angle_16_9 > 0.f &&
                           device_info.vertical_view_angle_16_9 > 0.f;
  bool has_fov_info_4_3 = device_info.horizontal_view_angle_4_3 > 0.f &&
                          device_info.vertical_view_angle_4_3 > 0.f;

  // Use the FOV information (16:9 or 4:3) whose aspect ratio is closer to the
  // ratio of sensor array size to calculate the sensor physical size.
  if (has_fov_info_16_9 && (is_closer_to_16_9 || !has_fov_info_4_3)) {
    update_static(ANDROID_SENSOR_INFO_PHYSICAL_SIZE,
                  GetPhysicalSize(device_info.horizontal_view_angle_16_9,
                                  device_info.vertical_view_angle_16_9,
                                  focal_length, aspect_ratio, 16.f / 9.f));
  } else if (has_fov_info_4_3) {
    update_static(ANDROID_SENSOR_INFO_PHYSICAL_SIZE,
                  GetPhysicalSize(device_info.horizontal_view_angle_4_3,
                                  device_info.vertical_view_angle_4_3,
                                  focal_length, aspect_ratio, 4.f / 3.f));
  } else if (device_info.sensor_info_physical_size_width > 0.f &&
             device_info.sensor_info_physical_size_height > 0.f) {
    // Since the sensor physical size might be incorrect, only use these values
    // when there are no view angle information.
    update_static(
        ANDROID_SENSOR_INFO_PHYSICAL_SIZE,
        std::vector<float>{device_info.sensor_info_physical_size_width,
                           device_info.sensor_info_physical_size_height});
  } else {
    LOGF(ERROR)
        << "Neither sensor physical size nor view angle information is found";
    return -EINVAL;
  }
  return update_static.ok() ? 0 : -EINVAL;
}

const camera_metadata_t* MetadataHandler::GetDefaultRequestSettings(
    int template_type) {
  if (!IsValidTemplateType(template_type)) {
    LOGF(ERROR) << "Invalid template request type: " << template_type;
    return nullptr;
  }
  return template_settings_[template_type].get();
}

bool MetadataHandler::ShouldEnableConstantFrameRate(
    const android::CameraMetadata* metadata) const {
  if (device_info_.constant_framerate_unsupported) {
    return false;
  }

  // TODO(shik): Add a helper function to do the exists() and find() combo, so
  // it's less likely to have typos in the tag name.

  if (metadata->exists(ANDROID_CONTROL_AE_TARGET_FPS_RANGE)) {
    camera_metadata_ro_entry entry =
        metadata->find(ANDROID_CONTROL_AE_TARGET_FPS_RANGE);
    if (entry.data.i32[0] == entry.data.i32[1]) {
      return true;
    }
  }

  if (metadata->exists(ANDROID_CONTROL_CAPTURE_INTENT)) {
    camera_metadata_ro_entry entry =
        metadata->find(ANDROID_CONTROL_CAPTURE_INTENT);
    switch (entry.data.u8[0]) {
      case ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_RECORD:
      case ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_SNAPSHOT:
        return true;
    }
  }

  return false;
}

int MetadataHandler::PreHandleRequest(int frame_number,
                                      const Size& resolution,
                                      android::CameraMetadata* metadata) {
  DCHECK(thread_checker_.CalledOnValidThread());
  MetadataUpdater update_request(metadata);

  if (!device_info_.constant_framerate_unsupported) {
    bool enable = ShouldEnableConstantFrameRate(metadata);
    if (device_->SetControlValue(kControlExposureAutoPriority,
                                 enable ? 0 : 1) != 0) {
      LOGF(WARNING) << "Failed to set constant frame rate to " << std::boolalpha
                    << enable;
    }
  }

  if (metadata->exists(ANDROID_CONTROL_AF_TRIGGER)) {
    camera_metadata_entry entry = metadata->find(ANDROID_CONTROL_AF_TRIGGER);
    if (entry.data.u8[0] == ANDROID_CONTROL_AF_TRIGGER_START) {
      af_trigger_ = true;
    } else if (entry.data.u8[0] == ANDROID_CONTROL_AF_TRIGGER_CANCEL) {
      af_trigger_ = false;
    }
  }

  if (metadata->exists(ANDROID_CONTROL_AF_MODE)) {
    camera_metadata_entry entry = metadata->find(ANDROID_CONTROL_AF_MODE);
    if (entry.data.u8[0] == ANDROID_CONTROL_AF_MODE_OFF) {
      if (metadata->exists(ANDROID_LENS_FOCUS_DISTANCE) &&
          focus_distance_normalize_factor_ > 0) {
        entry = metadata->find(ANDROID_LENS_FOCUS_DISTANCE);
        int32_t distance =
            static_cast<int32_t>(entry.data.f[0] *
                                 focus_distance_normalize_factor_) +
            focus_distance_range_.minimum;
        distance = std::min(distance, focus_distance_range_.maximum);
        device_->SetAutoFocus(false);
        device_->SetFocusDistance(distance);
        int32_t focus_distance;
        device_->GetControlValue(kControlFocusDistance, &focus_distance);
        float simulate_diopters =
            static_cast<float>(focus_distance - focus_distance_range_.minimum) /
            focus_distance_normalize_factor_;
        update_request(ANDROID_LENS_FOCUS_DISTANCE, simulate_diopters);
      } else {
        device_->SetAutoFocus(false);
      }
    } else if (entry.data.u8[0] == ANDROID_CONTROL_AF_MODE_AUTO) {
      device_->SetAutoFocus(true);
      float diopters;
      if (device_info_.lens_info_optimal_focus_distance > 0) {
        diopters = 1.0 / device_info_.lens_info_optimal_focus_distance;
      } else {
        diopters = 1.0 / kDefaultLensFocusDistance;
      }
      update_request(ANDROID_LENS_FOCUS_DISTANCE, diopters);
    }
  }

  if (is_awb_control_supported_ && metadata->exists(ANDROID_CONTROL_AWB_MODE)) {
    camera_metadata_entry entry = metadata->find(ANDROID_CONTROL_AWB_MODE);
    auto mode = static_cast<camera_metadata_enum_android_control_awb_mode>(
        entry.data.u8[0]);
    if (awb_temperature_.count(mode))
      device_->SetColorTemperature(awb_temperature_[mode]);
    else
      LOGF(WARNING) << "Unsupported AWB mode:" << mode;
  }

  const int64_t rolling_shutter_skew = 33'300'000;
  update_request(ANDROID_SENSOR_ROLLING_SHUTTER_SKEW, rolling_shutter_skew);

  if (metadata->exists(kVendorTagControlBrightness)) {
    camera_metadata_entry entry = metadata->find(kVendorTagControlBrightness);
    device_->SetControlValue(kControlBrightness, entry.data.i32[0]);
  }

  if (metadata->exists(kVendorTagControlContrast)) {
    camera_metadata_entry entry = metadata->find(kVendorTagControlContrast);
    device_->SetControlValue(kControlContrast, entry.data.i32[0]);
  }

  if (metadata->exists(kVendorTagControlPan)) {
    camera_metadata_entry entry = metadata->find(kVendorTagControlPan);
    device_->SetControlValue(kControlPan, entry.data.i32[0]);
  }

  if (metadata->exists(kVendorTagControlSaturation)) {
    camera_metadata_entry entry = metadata->find(kVendorTagControlSaturation);
    device_->SetControlValue(kControlSaturation, entry.data.i32[0]);
  }

  if (metadata->exists(kVendorTagControlSharpness)) {
    camera_metadata_entry entry = metadata->find(kVendorTagControlSharpness);
    device_->SetControlValue(kControlSharpness, entry.data.i32[0]);
  }

  if (metadata->exists(kVendorTagControlTilt)) {
    camera_metadata_entry entry = metadata->find(kVendorTagControlTilt);
    device_->SetControlValue(kControlTilt, entry.data.i32[0]);
  }

  if (metadata->exists(kVendorTagControlZoom)) {
    camera_metadata_entry entry = metadata->find(kVendorTagControlZoom);
    device_->SetControlValue(kControlZoom, entry.data.i32[0]);
  }

  if (metadata->exists(ANDROID_CONTROL_AE_MODE)) {
    camera_metadata_entry entry = metadata->find(ANDROID_CONTROL_AE_MODE);
    switch (entry.data.u8[0]) {
      case ANDROID_CONTROL_AE_MODE_ON: {
        device_->SetExposureTimeHundredUs(kExposureTimeAuto);
        const int64_t exposure_time = 16'600'000;
        update_request(ANDROID_SENSOR_EXPOSURE_TIME, exposure_time);
        break;
      }

      case ANDROID_CONTROL_AE_MODE_OFF: {
        if (metadata->exists(ANDROID_SENSOR_EXPOSURE_TIME)) {
          int32_t exposure_time;
          entry = metadata->find(ANDROID_SENSOR_EXPOSURE_TIME);
          exposure_time =
              static_cast<int32_t>(entry.data.i64[0] / (100 * 1000));  // ns
          device_->SetExposureTimeHundredUs(exposure_time);
          device_->GetControlValue(kControlExposureTime, &exposure_time);
          update_request(
              ANDROID_SENSOR_EXPOSURE_TIME,
              base::strict_cast<int64_t>(exposure_time) * 100 * 1000);  // ns
        } else {
          LOGF(WARNING) << "There is no ANDROID_SENSOR_EXPOSURE_TIME metadata";
        }
        break;
      }

      default:
        LOGF(WARNING) << "Unsupport AE mode " << entry.data.u8[0];
        break;
    }
  }

  current_frame_number_ = frame_number;
  return 0;
}

int MetadataHandler::PostHandleRequest(
    int frame_number,
    int64_t timestamp,
    const Size& resolution,
    const std::vector<human_sensing::CrosFace>& faces,
    android::CameraMetadata* metadata) {
  DCHECK(thread_checker_.CalledOnValidThread());
  if (current_frame_number_ != frame_number) {
    LOGF(ERROR)
        << "Frame number mismatch in PreHandleRequest and PostHandleRequest";
    return -EINVAL;
  }

  MetadataUpdater update_request(metadata);
  // android.control
  // For USB camera, we don't know the AE state. Set the state to converged to
  // indicate the frame should be good to use. Then apps don't have to wait the
  // AE state.
  update_request(ANDROID_CONTROL_AE_STATE, ANDROID_CONTROL_AE_STATE_CONVERGED);
  update_request(ANDROID_CONTROL_AE_LOCK, ANDROID_CONTROL_AE_LOCK_OFF);

  // For USB camera, the USB camera handles everything and we don't have control
  // over AF. We only simply fake the AF metadata based on the request
  // received here.
  uint8_t af_state;
  if (af_trigger_) {
    af_state = ANDROID_CONTROL_AF_STATE_FOCUSED_LOCKED;
  } else {
    af_state = ANDROID_CONTROL_AF_STATE_INACTIVE;
  }
  update_request(ANDROID_CONTROL_AF_STATE, af_state);

  // Set AWB state to converged to indicate the frame should be good to use.
  update_request(ANDROID_CONTROL_AWB_STATE,
                 ANDROID_CONTROL_AWB_STATE_CONVERGED);

  update_request(ANDROID_CONTROL_AWB_LOCK, ANDROID_CONTROL_AWB_LOCK_OFF);

  camera_metadata_entry active_array_size =
      static_metadata_.find(ANDROID_SENSOR_INFO_ACTIVE_ARRAY_SIZE);

  if (active_array_size.count == 0) {
    LOGF(ERROR) << "Active array size is not found.";
    return -EINVAL;
  }

  // android.lens
  // Since android.lens.focalLength, android.lens.focusDistance and
  // android.lens.aperture are all fixed. And we don't support
  // android.lens.filterDensity so we can set the state to stationary.
  update_request(ANDROID_LENS_STATE, ANDROID_LENS_STATE_STATIONARY);

  // android.scaler
  update_request(ANDROID_SCALER_CROP_REGION, std::vector<int32_t>{
                                                 0,
                                                 0,
                                                 active_array_size.data.i32[2],
                                                 active_array_size.data.i32[3],
                                             });

  // android.sensor
  update_request(ANDROID_SENSOR_TIMESTAMP, timestamp);

  // android.statistics
  if (device_info_.enable_face_detection) {
    std::vector<int32_t> face_rectangles;
    std::vector<uint8_t> face_scores;
    for (auto& face : faces) {
      float x1 = std::max(face.bounding_box.x1,
                          static_cast<float>(active_array_size.data.i32[0]));
      float x2 =
          std::min(face.bounding_box.x2,
                   static_cast<float>(active_array_size.data.i32[0] +
                                      active_array_size.data.i32[2] - 1));
      float y1 = std::max(face.bounding_box.y1,
                          static_cast<float>(active_array_size.data.i32[1]));
      float y2 =
          std::min(face.bounding_box.y2,
                   static_cast<float>(active_array_size.data.i32[1] +
                                      active_array_size.data.i32[3] - 1));
      face_rectangles.push_back(x1);
      face_rectangles.push_back(y1);
      face_rectangles.push_back(x2);
      face_rectangles.push_back(y2);
      face_scores.push_back(face.confidence * 100);
    }
    update_request(ANDROID_STATISTICS_FACE_RECTANGLES, face_rectangles);
    update_request(ANDROID_STATISTICS_FACE_SCORES, face_scores);
    if (device_info_.region_of_interest_supported) {
      Rect<int> roi(
          active_array_size.data.i32[0], active_array_size.data.i32[1],
          active_array_size.data.i32[2], active_array_size.data.i32[3]);
      if (faces.size() == 1) {
        roi = Rect<int>(face_rectangles[0], face_rectangles[1],
                        face_rectangles[2] - face_rectangles[0] + 1,
                        face_rectangles[3] - face_rectangles[1] + 1);
      }
      device_->SetRegionOfInterest(roi);
    }
  }

  update_request(ANDROID_STATISTICS_LENS_SHADING_MAP_MODE,
                 ANDROID_STATISTICS_LENS_SHADING_MAP_MODE_OFF);

  update_request(ANDROID_STATISTICS_SCENE_FLICKER,
                 ANDROID_STATISTICS_SCENE_FLICKER_NONE);

  int32_t value;
  if (is_brightness_control_supported_ &&
      device_->GetControlValue(kControlBrightness, &value) == 0)
    update_request(kVendorTagControlBrightness, value);

  if (is_contrast_control_supported_ &&
      device_->GetControlValue(kControlContrast, &value) == 0)
    update_request(kVendorTagControlContrast, value);

  if (is_pan_control_supported_ &&
      device_->GetControlValue(kControlPan, &value) == 0)
    update_request(kVendorTagControlPan, value);

  if (is_saturation_control_supported_ &&
      device_->GetControlValue(kControlSaturation, &value) == 0)
    update_request(kVendorTagControlSaturation, value);

  if (is_sharpness_control_supported_ &&
      device_->GetControlValue(kControlSharpness, &value) == 0)
    update_request(kVendorTagControlSharpness, value);

  if (is_tilt_control_supported_ &&
      device_->GetControlValue(kControlTilt, &value) == 0)
    update_request(kVendorTagControlTilt, value);

  if (is_zoom_control_supported_ &&
      device_->GetControlValue(kControlZoom, &value) == 0)
    update_request(kVendorTagControlZoom, value);

  if (metadata->exists(ANDROID_CONTROL_AWB_MODE)) {
    update_request(ANDROID_CONTROL_AWB_MODE, ANDROID_CONTROL_AWB_MODE_AUTO);
    if (is_awb_control_supported_ &&
        device_->GetControlValue(kControlAutoWhiteBalance, &value) == 0) {
      if (!value &&  // Not auto white balance.
          device_->GetControlValue(kControlWhiteBalanceTemperature, &value) ==
              0) {
        for (auto& mode_temperature : awb_temperature_) {
          if (value == mode_temperature.second) {
            update_request(ANDROID_CONTROL_AWB_MODE, mode_temperature.first);
            break;
          }
        }
      }
    }
  }

  return 0;
}

bool MetadataHandler::IsValidTemplateType(int template_type) {
  return template_type > 0 && template_type < CAMERA3_TEMPLATE_COUNT;
}

ScopedCameraMetadata MetadataHandler::CreateDefaultRequestSettings(
    int template_type) {
  android::CameraMetadata data(request_template_);

  int ret;
  switch (template_type) {
    case CAMERA3_TEMPLATE_PREVIEW:
      ret = FillDefaultPreviewSettings(&data);
      break;
    case CAMERA3_TEMPLATE_STILL_CAPTURE:
      ret = FillDefaultStillCaptureSettings(&data);
      break;
    case CAMERA3_TEMPLATE_VIDEO_RECORD:
      ret = FillDefaultVideoRecordSettings(&data);
      break;
    case CAMERA3_TEMPLATE_VIDEO_SNAPSHOT:
      ret = FillDefaultVideoSnapshotSettings(&data);
      break;
    case CAMERA3_TEMPLATE_ZERO_SHUTTER_LAG:
      ret = FillDefaultZeroShutterLagSettings(&data);
      break;
    case CAMERA3_TEMPLATE_MANUAL:
      ret = FillDefaultManualSettings(&data);
      break;
    default:
      LOGF(ERROR) << "Invalid template request type: " << template_type;
      return NULL;
  }

  if (ret) {
    return ScopedCameraMetadata();
  }
  return ScopedCameraMetadata(data.release());
}

int MetadataHandler::FillDefaultPreviewSettings(
    android::CameraMetadata* metadata) {
  MetadataUpdater update_request(metadata);

  // android.control
  update_request(ANDROID_CONTROL_CAPTURE_INTENT,
                 ANDROID_CONTROL_CAPTURE_INTENT_PREVIEW);
  update_request(ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
                 std::vector<int32_t>{kMinFps, max_supported_fps_});
  update_request(ANDROID_CONTROL_MODE, ANDROID_CONTROL_MODE_AUTO);

  // android.jpeg
  update_request(ANDROID_JPEG_THUMBNAIL_SIZE, std::vector<int32_t>{0, 0});
  return 0;
}

int MetadataHandler::FillDefaultStillCaptureSettings(
    android::CameraMetadata* metadata) {
  MetadataUpdater update_request(metadata);

  // android.colorCorrection
  update_request(ANDROID_COLOR_CORRECTION_ABERRATION_MODE,
                 ANDROID_COLOR_CORRECTION_ABERRATION_MODE_HIGH_QUALITY);

  // android.control
  update_request(ANDROID_CONTROL_CAPTURE_INTENT,
                 ANDROID_CONTROL_CAPTURE_INTENT_STILL_CAPTURE);
  update_request(ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
                 std::vector<int32_t>{kMinFps, max_supported_fps_});

  update_request(ANDROID_CONTROL_MODE, ANDROID_CONTROL_MODE_AUTO);
  return 0;
}

int MetadataHandler::FillDefaultVideoRecordSettings(
    android::CameraMetadata* metadata) {
  MetadataUpdater update_request(metadata);

  // android.control
  update_request(ANDROID_CONTROL_CAPTURE_INTENT,
                 ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_RECORD);
  if (device_info_.constant_framerate_unsupported) {
    update_request(ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
                   std::vector<int32_t>{kMinFps, max_supported_fps_});
  } else {
    update_request(
        ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
        std::vector<int32_t>{max_supported_fps_, max_supported_fps_});
  }

  update_request(ANDROID_CONTROL_MODE, ANDROID_CONTROL_MODE_AUTO);
  return 0;
}

int MetadataHandler::FillDefaultVideoSnapshotSettings(
    android::CameraMetadata* metadata) {
  MetadataUpdater update_request(metadata);

  // android.control
  update_request(ANDROID_CONTROL_CAPTURE_INTENT,
                 ANDROID_CONTROL_CAPTURE_INTENT_VIDEO_SNAPSHOT);
  if (device_info_.constant_framerate_unsupported) {
    update_request(ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
                   std::vector<int32_t>{kMinFps, max_supported_fps_});
  } else {
    update_request(
        ANDROID_CONTROL_AE_TARGET_FPS_RANGE,
        std::vector<int32_t>{max_supported_fps_, max_supported_fps_});
  }

  update_request(ANDROID_CONTROL_MODE, ANDROID_CONTROL_MODE_AUTO);
  return 0;
}

int MetadataHandler::FillDefaultZeroShutterLagSettings(
    android::CameraMetadata* /*metadata*/) {
  // Do not support ZSL template.
  return -EINVAL;
}

int MetadataHandler::FillDefaultManualSettings(
    android::CameraMetadata* /*metadata*/) {
  // Do not support manual template.
  return -EINVAL;
}

}  // namespace cros
